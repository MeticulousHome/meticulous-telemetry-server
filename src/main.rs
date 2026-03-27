mod auth;
mod fetching;
mod read_write;
mod types;

use actix_cors::Cors;
use actix_web::{App, HttpServer, http::Uri, web};
use dotenv::from_filename;
use google_oauth::Client;
use std::{env, io, sync::RwLock};

use crate::{
    read_write::{build_entry_index, list_upload_file_names},
    types::AppState,
};

const ENV_FILE: &str = ".env";
const JWT_SECRET_KEY: &str = "JWT_SECRET";
const ALLOWED_DOMAINS_KEY: &str = "ALLOWED_DOMAINS";
const ALLOWED_ORIGINS_KEY: &str = "ALLOWED_ORIGINS";
pub(crate) const JWT_EXPIRATION_HOURS: i64 = 24;
pub(crate) const UPLOADS_ROOT: &str = "./uploads";
pub(crate) const DOWNLOAD_BATCH_TIMESTAMP_FORMAT: &str = "%Y_%m_%d:%H_%M_%S";
pub(crate) const IS_DEV: bool = false;

fn load_app_state() -> io::Result<AppState> {
    from_filename(ENV_FILE)
        .map_err(|err| io::Error::other(format!("Failed to load {ENV_FILE}: {err}")))?;

    let allowed_domains = parse_allowed_domains(&get_required_env_var(ALLOWED_DOMAINS_KEY)?);
    let allowed_origins = parse_allowed_origins(&get_required_env_var(ALLOWED_ORIGINS_KEY)?)?;
    let jwt_secret = get_required_env_var(JWT_SECRET_KEY)?;
    let uploads_index = RwLock::new(build_entry_index(list_upload_file_names()?));

    Ok(AppState {
        google_client: Client::new(""),
        jwt_secret,
        allowed_domains,
        allowed_origins,
        uploads_index,
    })
}

fn get_required_env_var(key: &str) -> io::Result<String> {
    match env::var(key) {
        Ok(value) if !value.is_empty() => Ok(value),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Environment variable {key} is empty"),
        )),
        Err(err) => Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Failed to read environment variable {key}: {err}"),
        )),
    }
}

fn parse_allowed_domains(raw_domains: &str) -> Vec<String> {
    raw_domains
        .split(',')
        .map(str::trim)
        .filter(|domain| !domain.is_empty())
        .map(|domain| domain.to_ascii_lowercase())
        .collect()
}

pub(crate) fn parse_allowed_origins(raw_origins: &str) -> io::Result<Vec<String>> {
    let origins = raw_origins
        .split(',')
        .map(str::trim)
        .filter(|origin| !origin.is_empty())
        .map(normalize_allowed_origin)
        .collect::<io::Result<Vec<_>>>()?;

    if origins.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Environment variable {ALLOWED_ORIGINS_KEY} is empty"),
        ));
    }

    Ok(origins)
}

fn normalize_allowed_origin(origin: &str) -> io::Result<String> {
    let uri = origin.parse::<Uri>().map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid allowed origin {origin}: {err}"),
        )
    })?;

    let scheme = uri.scheme_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Allowed origin is missing scheme: {origin}"),
        )
    })?;
    let authority = uri.authority().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Allowed origin is missing host: {origin}"),
        )
    })?;

    if uri.path() != "/" || uri.query().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Allowed origin must not include a path or query: {origin}"),
        ));
    }

    Ok(format!("{scheme}://{authority}"))
}

pub(crate) fn is_valid_target(target: &str) -> bool {
    !target.is_empty()
        && target != "."
        && target != ".."
        && target.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '_' || character == '-'
        })
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    println!("Telemetry server starting...");
    let app_state = web::Data::new(load_app_state()?);

    HttpServer::new(move || {
        let cors = app_state
            .allowed_origins
            .iter()
            .fold(Cors::default(), |cors, origin| cors.allowed_origin(origin))
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
            .configure(auth::configure)
            .configure(fetching::configure)
            .configure(read_write::configure)
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
