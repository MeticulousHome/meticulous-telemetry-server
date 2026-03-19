#![feature(path_add_extension)]
use actix_multipart::form::MultipartForm;
use actix_multipart::form::{json::Json as MpJson, tempfile::TempFile};
use actix_web::{App, Error, HttpRequest, HttpResponse, HttpServer, get, post, web};
use chrono::prelude::*;
use dotenv::from_filename;
use google_oauth::{Client, GoogleAccessTokenPayload};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{env, fs, io, path::Path};

const ENV_FILE: &str = ".env";
const JWT_SECRET_KEY: &str = "JWT_SECRET";
const ALLOWED_DOMAINS_KEY: &str = "ALLOWED_DOMAINS";
const JWT_SECRET_DEFAULT: &str = "local-dev-jwt-secret";
const ALLOWED_DOMAINS_DEFAULT: &str = "meticuloushome.com,fffuego.com";
const JWT_EXPIRATION_HOURS: i64 = 24;

#[derive(Clone)]
struct AppState {
    google_client: Client,
    jwt_secret: String,
    allowed_domains: Vec<String>,
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

#[post("/upload/{target}")]
async fn upload(
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
    let path: std::path::PathBuf = Path::new("./uploads").join(target);

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

    Ok(AppState {
        google_client: Client::new(""),
        jwt_secret,
        allowed_domains,
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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Telemetry server starting...");
    let app_state = web::Data::new(load_app_state()?);

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .service(auth_google)
            .service(validate_token)
            .service(upload)
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
