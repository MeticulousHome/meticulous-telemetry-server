
#![feature(path_add_extension)]
use std::{fs, path::Path};
use chrono::prelude::*;
use actix_multipart::form::MultipartForm;
use actix_web::{post, web, App, HttpResponse, HttpServer, Error};
use regex::Regex;
use serde::Deserialize;
use actix_multipart::form::{json::Json as MpJson, tempfile::TempFile};

// Meticulous machine config is optional to be send with the debug shot file
#[derive(Debug, Deserialize)]
struct Metadata {
    config: serde_json::Value,
}

#[derive(Debug, MultipartForm)]
struct UploadDebugShotFile {
    #[multipart(limit = "1MB")]
    file: TempFile,
    json: MpJson<Metadata>,
}

#[post("/upload/{target}")]
async fn upload(MultipartForm(form): MultipartForm<UploadDebugShotFile>, path: web::Path<String>) -> Result<HttpResponse, Error> {
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
    let filename_from_date = Utc::now().format("%Y%m%y_%H%M%S").to_string();
    let path: std::path::PathBuf = Path::new("./uploads").join(target);
    let mut shot_file = path.join(filename_from_date.clone());
    let mut config_file = shot_file.clone();
    shot_file.add_extension("csv.zstd");
    config_file.add_extension("json");

    if let Err(e) = fs::create_dir_all(&path) {
        eprintln!("Failed to create directory {}: {}", path.to_str().unwrap(), e);
        return Ok(HttpResponse::InternalServerError().body(format!("Failed to create directory: {}", e)));
    }

    if let Err(e) = fs::copy(form.file.file.into_temp_path(), &shot_file) {
        eprintln!("Failed to save file {}:  {}",shot_file.to_str().unwrap(), e);
        return Ok(HttpResponse::InternalServerError().body(format!("Failed to save file: {}", e)));
    }


    let json_string = form.json.config.to_string();
    if let Err(e) = fs::write(config_file.clone(), json_string) {
        eprintln!("Failed to save config {}:  {}",config_file.to_str().unwrap(), e);
    } else {
        println!("Wrote config file {}", config_file.to_str().unwrap())
    }


    println!(
        "Uploaded file {}, with size: {}",
        shot_file.to_str().unwrap(), form.file.size
    );

    Ok(HttpResponse::Ok().body("File uploaded successfully"))

}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(move || App::new().service(upload))
        .bind(("0.0.0.0", 8080))?
        .run()
        .await
}