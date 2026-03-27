use actix_web::{Error, HttpRequest, HttpResponse, get, post, web};
use chrono::Utc;
use google_oauth::GoogleAccessTokenPayload;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};

use crate::{
    IS_DEV, JWT_EXPIRATION_HOURS,
    types::{AppState, ErrorResponse, GoogleAuthRequest, GoogleAuthResponse, LocalAuthClaims},
};

pub(crate) fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(auth_google).service(validate_token);
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

pub(crate) fn validate_auth_header(
    request: &HttpRequest,
    secret: &str,
) -> Result<GoogleAccessTokenPayload, HttpResponse> {
    if IS_DEV {
        return serde_json::from_value(serde_json::json!({
            "sub": "dev-user",
            "picture": null,
            "name": "Dev User",
            "locale": null,
            "given_name": "Dev",
            "email": "dev@local",
            "email_verified": true
        }))
        .map_err(|err| {
            eprintln!("Failed to construct dev auth payload: {err}");
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to construct dev auth payload".to_string(),
            })
        });
    }

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
