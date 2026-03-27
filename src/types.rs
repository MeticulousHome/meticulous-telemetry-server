use actix_multipart::form::MultipartForm;
use actix_multipart::form::{json::Json as MpJson, tempfile::TempFile};
use chrono::{NaiveDate, NaiveTime};
use google_oauth::{Client, GoogleAccessTokenPayload};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf, sync::RwLock};

pub(crate) struct AppState {
    pub(crate) google_client: Client,
    pub(crate) jwt_secret: String,
    pub(crate) allowed_domains: Vec<String>,
    pub(crate) allowed_origins: Vec<String>,
    pub(crate) uploads_index: RwLock<ParsedEntriesByName>,
}

// Meticulous machine config is optional to be send with the debug shot file
#[derive(Debug, Deserialize)]
pub(crate) struct Metadata {
    pub(crate) config: serde_json::Value,
}

#[derive(Debug, MultipartForm)]
pub(crate) struct UploadDebugShotFile {
    #[multipart(limit = "1MB")]
    pub(crate) file: TempFile,
    pub(crate) json: Option<MpJson<Metadata>>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct GoogleAuthRequest {
    pub(crate) token: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct GoogleAuthResponse {
    pub(crate) auth_token: String,
    pub(crate) user: GoogleAccessTokenPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LocalAuthClaims {
    pub(crate) exp: usize,
    pub(crate) iat: usize,
    #[serde(flatten)]
    pub(crate) user: GoogleAccessTokenPayload,
}

#[derive(Debug, Serialize)]
pub(crate) struct ErrorResponse {
    pub(crate) error: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct FetchQuery {
    pub(crate) target: Option<String>,
    pub(crate) date_range: Option<String>,
    pub(crate) page: Option<isize>,
    pub(crate) size: Option<isize>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AvailableMachinesQuery {
    pub(crate) date_range: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DownloadQuery {
    pub(crate) files: Option<String>,
    #[serde(rename = "skipDownload", default)]
    pub(crate) skip_download: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct FetchResponse {
    pub(crate) items: Vec<String>,
    pub(crate) size: usize,
    pub(crate) page: usize,
    #[serde(rename = "hasNext")]
    pub(crate) has_next: bool,
}

pub(crate) type ParsedEntriesByName = BTreeMap<String, BTreeMap<NaiveDate, Vec<String>>>;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct ParsedEntry {
    pub(crate) name: String,
    pub(crate) date: NaiveDate,
    pub(crate) time: NaiveTime,
    pub(crate) extension: String,
}

impl ParsedEntry {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        let (name, rest) = value.split_once('/')?;
        let (datetime_part, extension) = rest.split_once('.')?;
        let (date_str, time_str) = datetime_part.split_once('_')?;

        let date = NaiveDate::parse_from_str(date_str, "%Y%m%d").ok()?;
        let time = NaiveTime::parse_from_str(time_str, "%H%M%S").ok()?;

        Some(Self {
            name: name.to_string(),
            date,
            time,
            extension: extension.to_string(),
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DownloadEntry {
    pub(crate) relative_path: String,
    pub(crate) absolute_path: PathBuf,
    pub(crate) download_name: String,
}
