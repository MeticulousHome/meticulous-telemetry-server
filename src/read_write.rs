use actix_multipart::form::MultipartForm;
use actix_web::{Error, HttpRequest, HttpResponse, get, post, web};
use chrono::{DateTime, Utc};
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    io,
    path::{Path, PathBuf},
    process::Command,
};

use crate::{
    DOWNLOAD_BATCH_TIMESTAMP_FORMAT, UPLOADS_ROOT,
    auth::validate_auth_header,
    fetching::{parse_date_range, parse_target_filter},
    is_valid_target,
    types::{
        AppState, DownloadEntry, DownloadQuery, ErrorResponse, ParsedEntriesByName, ParsedEntry,
        UploadDebugShotFile,
    },
};

pub(crate) fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(download).service(upload);
}

#[get("/download")]
async fn download(
    state: web::Data<AppState>,
    request: HttpRequest,
    query: web::Query<DownloadQuery>,
) -> Result<HttpResponse, Error> {
    let _user = match validate_auth_header(&request, &state.jwt_secret) {
        Ok(user) => user,
        Err(response) => return Ok(response),
    };

    let entries = if query.files.is_some() {
        match resolve_download_entries_for_query(&query, None) {
            Ok(entries) => entries,
            Err(error) => {
                return Ok(HttpResponse::BadRequest().json(ErrorResponse { error }));
            }
        }
    } else {
        let index = match state.uploads_index.read() {
            Ok(index) => index,
            Err(err) => {
                eprintln!("Failed to read uploads index: {err}");
                return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                    error: "Failed to read uploads index".to_string(),
                }));
            }
        };

        match resolve_download_entries_for_query(&query, Some(&index)) {
            Ok(entries) => entries,
            Err(error) => {
                return Ok(HttpResponse::BadRequest().json(ErrorResponse { error }));
            }
        }
    };

    if entries.is_empty() {
        return Ok(HttpResponse::NotFound().json(ErrorResponse {
            error: "No files matched requested criteria".to_string(),
        }));
    }

    if let Some(missing_entry) = entries.iter().find(|entry| !entry.absolute_path.is_file()) {
        return Ok(HttpResponse::NotFound().json(ErrorResponse {
            error: format!("Requested file not found: {}", missing_entry.relative_path),
        }));
    }

    if entries.len() == 1 {
        let entry = entries.into_iter().next().unwrap();
        let relative_path = entry.relative_path.clone();
        let download_name = entry.download_name.clone();
        let read_path = entry.absolute_path;
        let (bytes, response_file_name) = match web::block(move || {
            read_download_payload(read_path, download_name)
        })
        .await
        {
            Ok(Ok(payload)) => payload,
            Ok(Err(err)) => {
                eprintln!("Failed to read requested file {relative_path}: {err}");
                return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                    error: "Failed to read requested file".to_string(),
                }));
            }
            Err(err) => {
                eprintln!("Failed to run file read in blocking task: {err}");
                return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                    error: "Failed to read requested file".to_string(),
                }));
            }
        };

        return Ok(HttpResponse::Ok()
            .append_header((
                "Content-Disposition",
                content_disposition_header_value(&response_file_name, query.skip_download),
            ))
            .content_type("application/octet-stream")
            .body(bytes));
    }

    let requested_paths = entries
        .iter()
        .map(|entry| entry.relative_path.clone())
        .collect::<Vec<_>>();
    let download_name = build_download_batch_name(Utc::now());
    let archive_paths = requested_paths.clone();
    let archive_bytes = match web::block(move || build_zip_archive(archive_paths)).await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(err)) => {
            eprintln!("Failed to create download archive: {err}");
            return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to create download archive".to_string(),
            }));
        }
        Err(err) => {
            eprintln!("Failed to run archive build in blocking task: {err}");
            return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to create download archive".to_string(),
            }));
        }
    };

    Ok(HttpResponse::Ok()
        .append_header((
            "Content-Disposition",
            content_disposition_header_value(&download_name, query.skip_download),
        ))
        .content_type("application/zip")
        .body(archive_bytes))
}

#[post("/upload/{target}")]
async fn upload(
    state: web::Data<AppState>,
    MultipartForm(form): MultipartForm<UploadDebugShotFile>,
    path: web::Path<String>,
) -> Result<HttpResponse, Error> {
    let target = path.into_inner();
    let form_filename = form.file.file_name.clone().unwrap_or_default();
    let is_json = form_filename.ends_with("json.zst");

    // Devices names are usually meticulousAdjectiveNoun and we are adding -SERIAL
    // for collision prevention. We are not checking for the serial number format
    // and we allow for a wider range so users can change their hostnames
    if !is_valid_target(&target) {
        return Ok(HttpResponse::BadRequest().body("Invalid target parameter"));
    }

    // We can never be fully sure that the client is not sending us a malicious filename
    // so we sanitize it by coming up with our own
    let filename_from_date = Utc::now().format("%Y%m%d_%H%M%S").to_string();
    let path = Path::new(UPLOADS_ROOT).join(target.clone());

    let mut shot_file = path.join(filename_from_date.clone());
    let mut config_file = shot_file.clone();

    // Detect the type of the uploaded file based on its name (if possible)
    println!("Original filename: {form_filename}");

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

    if let Err(err) = fs::create_dir_all(&path) {
        eprintln!(
            "Failed to create directory {}: {}",
            path.to_str().unwrap(),
            err
        );
        return Ok(
            HttpResponse::InternalServerError().body(format!("Failed to create directory: {err}"))
        );
    }

    if let Err(err) = fs::copy(form.file.file.into_temp_path(), &shot_file) {
        eprintln!(
            "Failed to save file {}:  {}",
            shot_file.to_str().unwrap(),
            err
        );
        return Ok(HttpResponse::InternalServerError().body(format!("Failed to save file: {err}")));
    }

    // The uploaded file is CSV file so it doesnt contain any config. We therefore have to save it manually
    if !is_json && form.json.is_some() {
        let json_string = form.json.unwrap().config.to_string();
        if let Err(err) = fs::write(config_file.clone(), json_string) {
            eprintln!(
                "Failed to save config {}:  {}",
                config_file.to_str().unwrap(),
                err
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

    if let Some(entry_name) = shot_file
        .strip_prefix(Path::new(UPLOADS_ROOT))
        .ok()
        .and_then(|relative_path| relative_path.to_str())
    {
        let mut index = match state.uploads_index.write() {
            Ok(index) => index,
            Err(err) => {
                eprintln!("Failed to update uploads index: {err}");
                return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                    error: "Failed to update uploads index".to_string(),
                }));
            }
        };
        let _ = insert_entry(&mut index, entry_name);
    }

    Ok(HttpResponse::Ok().body("File uploaded successfully"))
}

pub(crate) fn parse_download_entries(
    raw_files: Option<&str>,
) -> Result<Vec<DownloadEntry>, String> {
    let Some(raw_files) = raw_files else {
        return Err("Missing files parameter".to_string());
    };

    if raw_files.trim().is_empty() {
        return Err("Missing files parameter".to_string());
    }

    let mut entries = Vec::new();
    let mut seen_paths = BTreeSet::new();

    for raw_path in raw_files.split(',').map(str::trim) {
        if raw_path.is_empty() {
            return Err("Invalid files parameter".to_string());
        }

        if !seen_paths.insert(raw_path.to_string()) {
            continue;
        }

        entries.push(parse_download_entry(raw_path)?);
    }

    if entries.is_empty() {
        return Err("Missing files parameter".to_string());
    }

    Ok(entries)
}

pub(crate) fn resolve_download_entries_for_query(
    query: &DownloadQuery,
    uploads_index: Option<&ParsedEntriesByName>,
) -> Result<Vec<DownloadEntry>, String> {
    if query.files.is_some() {
        return parse_download_entries(query.files.as_deref());
    }

    let target_filter = parse_target_filter(query.target.as_deref())?;
    let date_range = parse_date_range(query.date_range.as_deref())?;

    if target_filter.is_none() && date_range.is_none() {
        return Err("Missing files, target, or date_range parameter".to_string());
    }

    let Some(index) = uploads_index else {
        return Err("Missing uploads index for target/date_range download query".to_string());
    };

    collect_download_entries_from_index(index, target_filter.as_ref(), date_range.as_ref())
}

fn collect_download_entries_from_index(
    index: &ParsedEntriesByName,
    target_filter: Option<&BTreeSet<String>>,
    date_range: Option<&(chrono::NaiveDate, chrono::NaiveDate)>,
) -> Result<Vec<DownloadEntry>, String> {
    let mut entries = Vec::new();
    let mut seen_paths = BTreeSet::new();

    for (name, dated_entries) in index.iter() {
        if target_filter.is_some_and(|target_filter| !target_filter.contains(name)) {
            continue;
        }

        for (date, date_entries) in dated_entries {
            if date_range.is_some_and(|(start_date, end_date)| date < start_date || date > end_date)
            {
                continue;
            }

            for entry in date_entries {
                if !seen_paths.insert(entry.clone()) {
                    continue;
                }

                entries.push(parse_download_entry(entry)?);
            }
        }
    }

    Ok(entries)
}

fn parse_download_entry(relative_path: &str) -> Result<DownloadEntry, String> {
    if relative_path.contains('\\') {
        return Err(format!("Invalid file path: {relative_path}"));
    }

    let mut parts = relative_path.split('/');
    let Some(folder) = parts.next() else {
        return Err(format!("Invalid file path: {relative_path}"));
    };
    let Some(filename) = parts.next() else {
        return Err(format!("Invalid file path: {relative_path}"));
    };

    if parts.next().is_some()
        || folder.is_empty()
        || filename.is_empty()
        || !is_valid_target(folder)
        || filename == "."
        || filename == ".."
    {
        return Err(format!("Invalid file path: {relative_path}"));
    }

    Ok(DownloadEntry {
        relative_path: format!("{folder}/{filename}"),
        absolute_path: Path::new(UPLOADS_ROOT).join(folder).join(filename),
        download_name: filename.to_string(),
    })
}

fn read_download_payload(
    path: PathBuf,
    download_name: String,
) -> io::Result<(Vec<u8>, String)> {
    let file_bytes = fs::read(path)?;

    return Ok((file_bytes, download_name));
}

pub(crate) fn build_download_batch_name(date_time: DateTime<Utc>) -> String {
    format!(
        "file_batch_{}.zip",
        date_time.format(DOWNLOAD_BATCH_TIMESTAMP_FORMAT)
    )
}

fn build_zip_archive(relative_paths: Vec<String>) -> io::Result<Vec<u8>> {
    let archive_path = env::temp_dir().join(format!(
        "meticulous-download-{}-{}.zip",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));

    let status = Command::new("zip")
        .current_dir(UPLOADS_ROOT)
        .arg("-q")
        .arg(&archive_path)
        .args(&relative_paths)
        .status()?;

    if !status.success() {
        let _ = fs::remove_file(&archive_path);
        return Err(io::Error::other(format!(
            "zip command failed with status {status}"
        )));
    }

    let archive_bytes = fs::read(&archive_path);
    let _ = fs::remove_file(&archive_path);
    archive_bytes
}

pub(crate) fn content_disposition_header_value(filename: &str, skip_download: bool) -> String {
    let disposition_type = if skip_download {
        "inline"
    } else {
        "attachment"
    };
    format!(
        "{disposition_type}; filename=\"{}\"",
        filename.replace('"', "_")
    )
}

pub(crate) fn list_upload_file_names() -> io::Result<Vec<String>> {
    let uploads_root = Path::new(UPLOADS_ROOT);
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

pub(crate) fn build_entry_index<I, S>(entries: I) -> ParsedEntriesByName
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

pub(crate) fn insert_entry(
    grouped_entries: &mut ParsedEntriesByName,
    entry: &str,
) -> Option<ParsedEntry> {
    let parsed_entry = ParsedEntry::parse(entry)?;
    grouped_entries
        .entry(parsed_entry.name.clone())
        .or_default()
        .entry(parsed_entry.date)
        .or_default()
        .push(entry.to_string());

    Some(parsed_entry)
}
