use actix_web::{Error, HttpRequest, HttpResponse, get, web};
use chrono::NaiveDate;
use std::collections::BTreeSet;

use crate::{
    auth::validate_auth_header,
    is_valid_target,
    types::{AppState, AvailableMachinesQuery, ErrorResponse, FetchQuery, FetchResponse},
};

pub(crate) fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(available_machines).service(fetch);
}

// list all machines with data
// return all directories inside ./uploads as an array
// except for ".." and "."
// is expected application/json content
#[get("/available_machines")]
async fn available_machines(
    state: web::Data<AppState>,
    request: HttpRequest,
    query: web::Query<AvailableMachinesQuery>,
) -> Result<HttpResponse, Error> {
    let _user = match validate_auth_header(&request, &state.jwt_secret) {
        Ok(user) => user,
        Err(response) => return Ok(response),
    };

    let date_range = match parse_date_range(query.date_range.as_deref()) {
        Ok(date_range) => date_range,
        Err(error) => {
            return Ok(HttpResponse::BadRequest().json(ErrorResponse { error }));
        }
    };

    let machines = match state.uploads_index.read() {
        Ok(index) => index
            .iter()
            .filter(|(_, dated_entries)| {
                date_range.as_ref().is_none_or(|(start_date, end_date)| {
                    dated_entries
                        .keys()
                        .any(|date| date >= start_date && date <= end_date)
                })
            })
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>(),
        Err(err) => {
            eprintln!("Failed to read uploads index: {err}");
            return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to read available machines".to_string(),
            }));
        }
    };

    Ok(HttpResponse::Ok().json(machines))
}

// reads query params
// `target`, `date_range`, `page`, `size`
// filters the in-memory uploads index and returns a paginated file list
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

pub(crate) fn normalize_query_pagination_value(
    value: Option<isize>,
    default_value: isize,
) -> usize {
    value.unwrap_or(default_value).max(1) as usize
}

pub(crate) fn parse_target_filter(
    raw_targets: Option<&str>,
) -> Result<Option<BTreeSet<String>>, String> {
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

    if targets.iter().any(|target| !is_valid_target(target)) {
        return Err("Invalid target parameter".to_string());
    }

    Ok(Some(targets))
}

pub(crate) fn parse_date_range(
    raw_date_range: Option<&str>,
) -> Result<Option<(NaiveDate, NaiveDate)>, String> {
    let Some(raw_date_range) = raw_date_range else {
        return Ok(None);
    };

    if raw_date_range.trim().is_empty() {
        return Ok(None);
    }

    let (start_date, end_date) = raw_date_range.split_once(',').ok_or_else(|| {
        format!(
            "{} : {}",
            "Invalid date_range parameter".to_string(),
            raw_date_range.to_string()
        )
    })?;

    let start_date = NaiveDate::parse_from_str(start_date.trim(), "%Y%m%d").map_err(|_| {
        format!(
            "{} : {}",
            "Invalid date_range parameter".to_string(),
            raw_date_range.to_string()
        )
    })?;
    let end_date = NaiveDate::parse_from_str(end_date.trim(), "%Y%m%d").map_err(|_| {
        format!(
            "{} : {}",
            "Invalid date_range parameter".to_string(),
            raw_date_range.to_string()
        )
    })?;

    if start_date <= end_date {
        Ok(Some((start_date, end_date)))
    } else {
        Ok(Some((end_date, start_date)))
    }
}
