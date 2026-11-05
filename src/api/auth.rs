use crate::config::AppConfig;
use crate::db::DbPool;
use argon2::{
    password_hash::{PasswordHash, PasswordVerifier},
    Argon2,
};
use axum::{
    extract::{Extension, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub user_id: i64,
    pub role: String,
    pub exp: usize,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub user_id: i64,
    pub username: String,
    pub role: String,
}

pub async fn login(
    State(pool): State<DbPool>,
    Extension(config): Extension<Arc<AppConfig>>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, String)> {
    let conn = pool
        .get()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let (user_id, username, password_hash, role, is_disabled): (i64, String, String, String, bool) =
        conn.query_row(
            "SELECT id, username, password_hash, role, is_disabled FROM users WHERE username = ?1",
            [&payload.username],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                "Invalid username or password".to_string(),
            )
        })?;

    if is_disabled {
        return Err((StatusCode::FORBIDDEN, "Account is disabled".to_string()));
    }

    // Verify argon2 password
    let parsed_hash = PasswordHash::new(&password_hash).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Invalid password hash in database".to_string(),
        )
    })?;

    if Argon2::default()
        .verify_password(payload.password.as_bytes(), &parsed_hash)
        .is_err()
    {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Invalid username or password".to_string(),
        ));
    }

    // Create JWT Token valid for 7 days
    let expiration = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::days(7))
        .expect("valid timestamp")
        .timestamp() as usize;

    let claims = Claims {
        sub: username.clone(),
        user_id,
        role: role.clone(),
        exp: expiration,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(config.jwt_secret.as_bytes()),
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to generate JWT: {}", e),
        )
    })?;

    // Log login to audit
    let _ = conn.execute(
        "INSERT INTO audit_logs (user_id, username, action, object_type, details) VALUES (?1, ?2, 'login', 'auth', 'User logged in successfully')",
        rusqlite::params![user_id, username],
    );

    Ok(Json(LoginResponse {
        token,
        user_id,
        username,
        role,
    }))
}

pub async fn get_me(
    State(pool): State<DbPool>,
    headers: HeaderMap,
    Extension(config): Extension<Arc<AppConfig>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_bearer_token(&headers)?;
    let claims = verify_jwt(&token, &config.jwt_secret)?;

    let conn = pool
        .get()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let (id, username, role, shell_mode): (i64, String, String, String) = conn
        .query_row(
            "SELECT id, username, role, shell_mode FROM users WHERE id = ?1",
            [claims.user_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .map_err(|_| (StatusCode::NOT_FOUND, "User not found".to_string()))?;

    Ok(Json(serde_json::json!({
        "id": id,
        "username": username,
        "role": role,
        "shell_mode": shell_mode
    })))
}

pub async fn change_password(
    State(pool): State<DbPool>,
    headers: HeaderMap,
    Extension(config): Extension<Arc<AppConfig>>,
    Json(payload): Json<ChangePasswordRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_bearer_token(&headers)?;
    let claims = verify_jwt(&token, &config.jwt_secret)?;
    if payload.new_password.len() < 12 || payload.new_password.contains(['\n', '\r', ':']) {
        return Err((
            StatusCode::BAD_REQUEST,
            "New password must be at least 12 characters and contain no colon or newline".into(),
        ));
    }
    let conn = pool
        .get()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let (username, current_hash): (String, String) = conn
        .query_row(
            "SELECT username, password_hash FROM users WHERE id = ?1 AND is_disabled = 0",
            [claims.user_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Account not found".to_string()))?;
    let parsed_hash = PasswordHash::new(&current_hash).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Invalid stored password hash".into(),
        )
    })?;
    if Argon2::default()
        .verify_password(payload.current_password.as_bytes(), &parsed_hash)
        .is_err()
    {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Current password is incorrect".into(),
        ));
    }
    use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
    let salt = SaltString::generate(&mut OsRng);
    let new_hash = Argon2::default()
        .hash_password(payload.new_password.as_bytes(), &salt)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .to_string();
    crate::core::ssh_user::set_linux_user_password(&username, &payload.new_password).map_err(
        |e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Linux password update failed: {}", e),
            )
        },
    )?;
    if let Err(error) = conn.execute(
        "UPDATE users SET password_hash = ?1, updated_at = datetime('now') WHERE id = ?2",
        rusqlite::params![new_hash, claims.user_id],
    ) {
        let _ =
            crate::core::ssh_user::set_linux_user_password(&username, &payload.current_password);
        return Err((StatusCode::INTERNAL_SERVER_ERROR, error.to_string()));
    }
    conn.execute(
        "UPDATE ssh_credentials SET initial_password = NULL WHERE user_id = ?1",
        [claims.user_id],
    )
    .ok();
    let _ = conn.execute(
        "INSERT INTO audit_logs (user_id, username, action, object_type, object_id, details)
        VALUES (?1, ?2, 'change_password', 'user', ?3, 'Password changed')",
        rusqlite::params![claims.user_id, username, claims.user_id.to_string()],
    );
    Ok(Json(serde_json::json!({"success": true})))
}

pub fn extract_bearer_token(headers: &HeaderMap) -> Result<String, (StatusCode, String)> {
    let auth_header = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "Missing Authorization header".to_string(),
        ))?;

    if !auth_header.starts_with("Bearer ") {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Invalid Authorization header format".to_string(),
        ));
    }

    Ok(auth_header["Bearer ".len()..].to_string())
}

pub fn verify_jwt(token: &str, secret: &str) -> Result<Claims, (StatusCode, String)> {
    use jsonwebtoken::{decode, DecodingKey, Validation};
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid or expired token".to_string(),
        )
    })?;

    Ok(token_data.claims)
}

pub async fn account_guard(
    State(pool): State<DbPool>,
    Extension(config): Extension<Arc<AppConfig>>,
    request: Request,
    next: Next,
) -> Result<Response, (StatusCode, String)> {
    if request.uri().path() == "/api/v2/auth/login" {
        return Ok(next.run(request).await);
    }
    let token = extract_bearer_token(request.headers())?;
    let claims = verify_jwt(&token, &config.jwt_secret)?;
    let conn = pool
        .get()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let (role, disabled): (String, bool) = conn
        .query_row(
            "SELECT role, is_disabled FROM users WHERE id = ?1",
            [claims.user_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Account no longer exists".into()))?;
    if disabled || role != claims.role {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Account access changed; sign in again".into(),
        ));
    }
    drop(conn);
    Ok(next.run(request).await)
}
