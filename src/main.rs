#![feature(path_add_extension)]
use actix_multipart::form::MultipartForm;
use actix_multipart::form::{json::Json as MpJson, tempfile::TempFile};
use actix_cors::Cors;
use actix_web::{App, Error, HttpRequest, HttpResponse, HttpServer, get, post, web};
use chrono::{NaiveDate, NaiveTime, prelude::*};
use dotenv::from_filename;
use google_oauth::{Client, GoogleAccessTokenPayload};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs, io,
    path::Path,
};
use std::sync::RwLock;

const ENV_FILE: &str = ".env";
const JWT_SECRET_KEY: &str = "JWT_SECRET";
const ALLOWED_DOMAINS_KEY: &str = "ALLOWED_DOMAINS";
const JWT_SECRET_DEFAULT: &str = "local-dev-jwt-secret";
const ALLOWED_DOMAINS_DEFAULT: &str = "meticuloushome.com,fffuego.com";
const JWT_EXPIRATION_HOURS: i64 = 24;

struct AppState {
    google_client: Client,
    jwt_secret: String,
    allowed_domains: Vec<String>,
    uploads_index: RwLock<ParsedEntriesByName>,
}

// Meticulous machine config is optional to be send with the debug shot file
#[derive(Debug, Deserialize)]
struct Metadata {
    config: serde_json::Value,
}

#[derive(Debug, MultipartForm)]
struct UploadDebugShotFile {
    #[multipart(limit = "1MB")]
    file: TempFile,
    json: Option<MpJson<Metadata>>,
}

#[derive(Debug, Deserialize)]
struct GoogleAuthRequest {
    token: String,
}

#[derive(Debug, Serialize)]
struct GoogleAuthResponse {
    auth_token: String,
    user: GoogleAccessTokenPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LocalAuthClaims {
    exp: usize,
    iat: usize,
    #[serde(flatten)]
    user: GoogleAccessTokenPayload,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Debug, Deserialize)]
struct FetchQuery {
    target: Option<String>,
    date_range: Option<String>,
    page: Option<isize>,
    size: Option<isize>,
}

#[derive(Debug, Serialize)]
struct FetchResponse {
    items: Vec<String>,
    size: usize,
    page: usize,
    #[serde(rename = "hasNext")]
    has_next: bool,
}

type ParsedEntriesByName = BTreeMap<String, BTreeMap<NaiveDate, Vec<String>>>;

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct ParsedEntry {
    name: String,
    date: NaiveDate,
    time: NaiveTime,
    extension: String,
}

fn parse_entry(s: &str) -> Option<ParsedEntry> {
    let (name, rest) = s.split_once('/')?;
    let (datetime_part, extension) = rest.split_once('.')?;
    let (date_str, time_str) = datetime_part.split_once('_')?;

    let date = NaiveDate::parse_from_str(date_str, "%Y%m%d").ok()?;
    let time = NaiveTime::parse_from_str(time_str, "%H%M%S").ok()?;

    Some(ParsedEntry {
        name: name.to_string(),
        date,
        time,
        extension: extension.to_string(),
    })
}

#[post("/auth/google")]
async fn auth_google(
    state: web::Data<AppState>,
    payload: web::Json<GoogleAuthRequest>,
) -> Result<HttpResponse, Error> {
    let client = state.google_client.clone();
    let token = payload.token.clone();

    let user = match web::block(move || client.validate_access_token(token)).await {
        Ok(Ok(user)) => {
            if !is_allowed_email_domain(user.email.as_deref(), &state.allowed_domains) {
                return Ok(HttpResponse::Unauthorized().json(ErrorResponse {
                    error: "Email domain not allowed".to_string(),
                }));
            }
            user
        }
        Ok(Err(err)) => {
            return Ok(HttpResponse::Unauthorized().json(ErrorResponse {
                error: format!("Invalid Google access token: {err}"),
            }));
        }
        Err(err) => {
            eprintln!("Failed to validate Google access token: {err}");
            return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to validate Google access token".to_string(),
            }));
        }
    };

    let auth_token = match encode_jwt(&user, &state.jwt_secret) {
        Ok(token) => token,
        Err(err) => {
            eprintln!("Failed to sign local auth token: {err}");
            return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to create local auth token".to_string(),
            }));
        }
    };

    Ok(HttpResponse::Ok().json(GoogleAuthResponse { auth_token, user }))
}

#[get("/available_machines")]
async fn available_machines(
    state: web::Data<AppState>,
    request: HttpRequest,
) -> Result<HttpResponse, Error> {
    let _user = match validate_auth_header(&request, &state.jwt_secret) {
        Ok(user) => user,
        Err(response) => return Ok(response),
    };

    let machines = match state.uploads_index.read() {
        Ok(index) => index.keys().cloned().collect::<Vec<_>>(),
        Err(err) => {
            eprintln!("Failed to read uploads index: {err}");
            return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to read available machines".to_string(),
            }));
        }
    };

    Ok(HttpResponse::Ok().json(machines))
}

#[get("/auth/validate_token")]
async fn validate_token(
    state: web::Data<AppState>,
    request: HttpRequest,
) -> Result<HttpResponse, Error> {
    let user = match validate_auth_header(&request, &state.jwt_secret) {
        Ok(user) => user,
        Err(response) => return Ok(response),
    };

    Ok(HttpResponse::Ok().json(user))
}

#[get("/fetch")]
async fn fetch(
    state: web::Data<AppState>,
    request: HttpRequest,
    query: web::Query<FetchQuery>,
) -> Result<HttpResponse, Error> {
    let _user = match validate_auth_header(&request, &state.jwt_secret) {
        Ok(user) => user,
        Err(response) => return Ok(response),
    };

    let target_filter = match parse_target_filter(query.target.as_deref()) {
        Ok(target_filter) => target_filter,
        Err(error) => {
            return Ok(HttpResponse::BadRequest().json(ErrorResponse { error }));
        }
    };

    let date_range = match parse_date_range(query.date_range.as_deref()) {
        Ok(date_range) => date_range,
        Err(error) => {
            return Ok(HttpResponse::BadRequest().json(ErrorResponse { error }));
        }
    };

    let final_list = match state.uploads_index.read() {
        Ok(index) => {
            let mut final_list = Vec::new();
            for (name, dated_entries) in index.iter() {
                if target_filter
                    .as_ref()
                    .is_some_and(|target_filter| !target_filter.contains(name))
                {
                    continue;
                }

                for (date, entries) in dated_entries {
                    if date_range
                        .as_ref()
                        .is_some_and(|(start_date, end_date)| date < start_date || date > end_date)
                    {
                        continue;
                    }

                    final_list.extend(entries.iter().cloned());
                }
            }
            final_list
        }
        Err(err) => {
            eprintln!("Failed to read uploads index: {err}");
            return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to fetch machine files".to_string(),
            }));
        }
    };

    let page = normalize_query_pagination_value(query.page, 1);
    let page_size = normalize_query_pagination_value(query.size, 50);
    let starting_index = page.saturating_sub(1).saturating_mul(page_size);

    if final_list.is_empty() || starting_index >= final_list.len() {
        return Ok(HttpResponse::Ok().json(FetchResponse {
            items: Vec::new(),
            size: 0,
            page,
            has_next: false,
        }));
    }

    let ending_index = page
        .saturating_mul(page_size)
        .saturating_sub(1)
        .min(final_list.len() - 1);
    let items = final_list[starting_index..ending_index + 1].to_vec();

    Ok(HttpResponse::Ok().json(FetchResponse {
        size: items.len(),
        page,
        has_next: ending_index < final_list.len() - 1,
        items,
    }))
}

fn normalize_query_pagination_value(value: Option<isize>, default_value: isize) -> usize {
    value.unwrap_or(default_value).max(1) as usize
}

fn parse_target_filter(raw_targets: Option<&str>) -> Result<Option<BTreeSet<String>>, String> {
    let Some(raw_targets) = raw_targets else {
        return Ok(None);
    };

    let targets = raw_targets
        .split(',')
        .map(str::trim)
        .filter(|target| !target.is_empty())
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>();

    if targets.is_empty() {
        return Ok(None);
    }

    let target_pattern = Regex::new(r"^[A-Za-z0-9_-]+$").unwrap();
    if targets
        .iter()
        .any(|target| !target_pattern.is_match(target))
    {
        return Err("Invalid target parameter".to_string());
    }

    Ok(Some(targets))
}

fn parse_date_range(raw_date_range: Option<&str>) -> Result<Option<(NaiveDate, NaiveDate)>, String> {
    let Some(raw_date_range) = raw_date_range else {
        return Ok(None);
    };

    if raw_date_range.trim().is_empty() {
        return Ok(None);
    }

    let (start_date, end_date) = raw_date_range
        .split_once(',')
        .ok_or_else(|| "Invalid date_range parameter".to_string())?;

    let start_date = NaiveDate::parse_from_str(start_date.trim(), "%Y%m%d")
        .map_err(|_| "Invalid date_range parameter".to_string())?;
    let end_date = NaiveDate::parse_from_str(end_date.trim(), "%Y%m%d")
        .map_err(|_| "Invalid date_range parameter".to_string())?;

    if start_date <= end_date {
        Ok(Some((start_date, end_date)))
    } else {
        Ok(Some((end_date, start_date)))
    }
}

#[post("/upload/{target}")]
async fn upload(
    state: web::Data<AppState>,
    MultipartForm(form): MultipartForm<UploadDebugShotFile>,
    path: web::Path<String>,
) -> Result<HttpResponse, Error> {
    // URL parameters
    let target = path.into_inner();

    // Devices names are usually meticulousAdjectiveNoun and we are adding -SERIAL
    // for collision prevention. We are not checking for the serial number format
    // and we allow for a wider range so users can change their hostnames
    let re = Regex::new(r"^[A-Za-z0-9_-]+$").unwrap();
    if !re.is_match(&target) {
        return Ok(HttpResponse::BadRequest().body("Invalid target parameter"));
    }

    // We can never be fully sure that the client is not sending us a malicious filename
    // so we sanitize it by coming up with our own
    let filename_from_date = Utc::now().format("%Y%m%d_%H%M%S").to_string();
    let path: std::path::PathBuf = Path::new("./uploads").join(&target);

    let mut shot_file = path.join(filename_from_date.clone());
    let mut config_file = shot_file.clone();

    // Detect the type of the uploaded file based on its name (if possible)
    let form_filename = form.file.file_name.unwrap_or("".to_string());
    let is_json = form_filename.ends_with("json.zst");
    println!("Original filename: {}", form_filename);

    if is_json {
        let parts: Vec<&str> = form_filename.split('.').collect();
        if parts.len() >= 3 {
            let shot_type = parts[parts.len() - 3];
            shot_file.add_extension(shot_type);
        } else {
            shot_file.add_extension("debug");
        }
        shot_file.add_extension("json.zstd");
        println!("A json debug file was uploaded. Skipping config creation");
    } else {
        shot_file.add_extension("csv.zstd");
        config_file.add_extension("json");
    }

    if let Err(e) = fs::create_dir_all(&path) {
        eprintln!(
            "Failed to create directory {}: {}",
            path.to_str().unwrap(),
            e
        );
        return Ok(
            HttpResponse::InternalServerError().body(format!("Failed to create directory: {}", e))
        );
    }

    if let Err(e) = fs::copy(form.file.file.into_temp_path(), &shot_file) {
        eprintln!(
            "Failed to save file {}:  {}",
            shot_file.to_str().unwrap(),
            e
        );
        return Ok(HttpResponse::InternalServerError().body(format!("Failed to save file: {}", e)));
    }

    // The uploaded file is CSV file so it doesnt contain any config. We therefore have to save it manually
    if !is_json && form.json.is_some() {
        let json_string = form.json.unwrap().config.to_string();
        if let Err(e) = fs::write(config_file.clone(), json_string) {
            eprintln!(
                "Failed to save config {}:  {}",
                config_file.to_str().unwrap(),
                e
            );
        } else {
            println!("Wrote config file {}", config_file.to_str().unwrap())
        }
    }

    println!(
        "Uploaded file {}, with size: {} bytes",
        shot_file.to_str().unwrap(),
        form.file.size
    );

    if let Some(file_name) = shot_file.file_name().and_then(|name| name.to_str()) {
        let entry_name = format!("{target}/{file_name}");
        let mut index = match state.uploads_index.write() {
            Ok(index) => index,
            Err(err) => {
                eprintln!("Failed to update uploads index: {err}");
                return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                    error: "Failed to update uploads index".to_string(),
                }));
            }
        };
        let _ = insert_entry(&mut index, &entry_name);
    }

    Ok(HttpResponse::Ok().body("File uploaded successfully"))
}

fn load_app_state() -> io::Result<AppState> {
    if let Err(err) = from_filename(ENV_FILE) {
        if !matches!(err.not_found(), true) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to load {ENV_FILE}: {err}"),
            ));
        }
    }

    let allowed_domains = parse_allowed_domains(&get_env_var_or_default(
        ALLOWED_DOMAINS_KEY,
        ALLOWED_DOMAINS_DEFAULT,
    ));
    let jwt_secret = get_env_var_or_default(JWT_SECRET_KEY, JWT_SECRET_DEFAULT);
    let uploads_index = RwLock::new(build_entry_index(list_upload_file_names()?));

    Ok(AppState {
        google_client: Client::new(""),
        jwt_secret,
        allowed_domains,
        uploads_index,
    })
}

fn get_env_var_or_default(key: &str, default_value: &str) -> String {
    if let Ok(value) = env::var(key) {
        if !value.is_empty() {
            return value;
        }
    }

    default_value.to_string()
}

fn parse_allowed_domains(raw_domains: &str) -> Vec<String> {
    raw_domains
        .split(',')
        .map(str::trim)
        .filter(|domain| !domain.is_empty())
        .map(|domain| domain.to_ascii_lowercase())
        .collect()
}

fn is_allowed_email_domain(email: Option<&str>, allowed_domains: &[String]) -> bool {
    if allowed_domains.is_empty() {
        return true;
    }

    let Some(email) = email else {
        return false;
    };

    let Some((_, domain)) = email.rsplit_once('@') else {
        return false;
    };

    let domain = domain.trim().to_ascii_lowercase();
    allowed_domains.iter().any(|allowed| allowed == &domain)
}

fn encode_jwt(
    payload: &GoogleAccessTokenPayload,
    secret: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now();
    let claims = LocalAuthClaims {
        iat: now.timestamp() as usize,
        exp: (now + chrono::Duration::hours(JWT_EXPIRATION_HOURS)).timestamp() as usize,
        user: payload.clone(),
    };
    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret(secret.as_bytes());
    encode(&header, &claims, &key)
}

fn validate_auth_header(
    request: &HttpRequest,
    secret: &str,
) -> Result<GoogleAccessTokenPayload, HttpResponse> {
    let Some(header_value) = request
        .headers()
        .get("Authorization")
        .or_else(|| request.headers().get("auth"))
    else {
        return Err(HttpResponse::Unauthorized().json(ErrorResponse {
            error: "Missing auth header".to_string(),
        }));
    };

    let Ok(header_value) = header_value.to_str() else {
        return Err(HttpResponse::Unauthorized().json(ErrorResponse {
            error: "Invalid auth header".to_string(),
        }));
    };

    let token = header_value
        .strip_prefix("Bearer ")
        .unwrap_or(header_value)
        .trim();
    if token.is_empty() {
        return Err(HttpResponse::Unauthorized().json(ErrorResponse {
            error: "Missing auth token".to_string(),
        }));
    }

    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;

    decode::<LocalAuthClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map(|token_data| token_data.claims.user)
    .map_err(|err| {
        eprintln!("Invalid auth token: {err}");
        HttpResponse::Unauthorized().json(ErrorResponse {
            error: "Invalid auth token".to_string(),
        })
    })
}

fn list_upload_file_names() -> io::Result<Vec<String>> {
    let uploads_root = Path::new("./uploads");
    let mut file_names = Vec::new();
    collect_upload_file_names(uploads_root, uploads_root, &mut file_names)?;
    file_names.sort();
    Ok(file_names)
}

fn collect_upload_file_names(
    uploads_root: &Path,
    current_path: &Path,
    file_names: &mut Vec<String>,
) -> io::Result<()> {
    let entries = match fs::read_dir(current_path) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };

    for entry in entries {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();

        if file_type.is_dir() {
            collect_upload_file_names(uploads_root, &path, file_names)?;
            continue;
        }

        if !file_type.is_file() {
            continue;
        }

        let Ok(relative_path) = path.strip_prefix(uploads_root) else {
            continue;
        };

        let parts = relative_path
            .iter()
            .map(|component| component.to_str())
            .collect::<Option<Vec<_>>>();
        let Some(parts) = parts else {
            continue;
        };

        file_names.push(parts.join("/"));
    }

    Ok(())
}

fn build_entry_index<I, S>(entries: I) -> ParsedEntriesByName
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut grouped_entries = BTreeMap::new();
    for entry in entries {
        let _ = insert_entry(&mut grouped_entries, entry.as_ref());
    }
    grouped_entries
}

fn insert_entry(grouped_entries: &mut ParsedEntriesByName, entry: &str) -> Option<ParsedEntry> {
    let parsed_entry = parse_entry(entry)?;
    grouped_entries
        .entry(parsed_entry.name.clone())
        .or_default()
        .entry(parsed_entry.date)
        .or_default()
        .push(entry.to_string());

    Some(parsed_entry)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Telemetry server starting...");
    let app_state = web::Data::new(load_app_state()?);

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allowed_methods(vec!["GET", "POST", "OPTIONS"])
            .allowed_headers(vec![
                actix_web::http::header::AUTHORIZATION,
                actix_web::http::header::CONTENT_TYPE,
                actix_web::http::header::HeaderName::from_static("auth"),
            ])
            .max_age(86_400);

        App::new()
            .wrap(cors)
            .app_data(app_state.clone())
            .service(auth_google)
            .service(available_machines)
            .service(fetch)
            .service(validate_token)
            .service(upload)
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
