use crate::api::auth::{extract_bearer_token, verify_jwt};
use crate::config::AppConfig;
use crate::core::ssh_user::{delete_linux_user, generate_credentials, provision_linux_user};
use crate::db::models::{SshCredential, User};
use crate::db::DbPool;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use axum::{
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: Option<String>,
    pub role: Option<String>,       // "tenant" | "admin"
    pub shell_mode: Option<String>, // "sftp_only" | "standard_shell" | "sudo_admin"
}

#[derive(Debug, Serialize)]
pub struct UserCreatedResponse {
    pub user: User,
    pub ssh_credentials: SshCredential,
}

pub async fn list_users(
    State(pool): State<DbPool>,
    headers: HeaderMap,
    Extension(config): Extension<Arc<AppConfig>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_bearer_token(&headers)?;
    let claims = verify_jwt(&token, &config.jwt_secret)?;

    let conn = pool
        .get()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut stmt = conn
        .prepare(
            "SELECT id, username, password_hash, role, shell_mode, is_disabled, created_at, updated_at 
             FROM users ORDER BY id ASC",
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let users_iter = stmt
        .query_map([], |row| {
            Ok(User {
                id: row.get(0)?,
                username: row.get(1)?,
                password_hash: row.get(2)?,
                role: row.get(3)?,
                shell_mode: row.get(4)?,
                is_disabled: row.get(5)?,
                created_at: row.get(6)?,
                updated_at: row.get(7)?,
            })
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut users = Vec::new();
    for u in users_iter {
        let user = u.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        // If not admin, can only see self
        if claims.role != "admin" && user.id != claims.user_id {
            continue;
        }
        users.push(user);
    }

    Ok(Json(users))
}

pub async fn create_user(
    State(pool): State<DbPool>,
    headers: HeaderMap,
    Extension(config): Extension<Arc<AppConfig>>,
    Json(payload): Json<CreateUserRequest>,
) -> Result<Json<UserCreatedResponse>, (StatusCode, String)> {
    let token = extract_bearer_token(&headers)?;
    let claims = verify_jwt(&token, &config.jwt_secret)?;

    if claims.role != "admin" {
        return Err((
            StatusCode::FORBIDDEN,
            "Only administrators can create users".to_string(),
        ));
    }

    let username = payload.username.trim().to_lowercase();
    if username.is_empty()
        || !username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "Username must be non-empty and alphanumeric".to_string(),
        ));
    }

    let role = payload.role.unwrap_or_else(|| "tenant".to_string());
    let shell_mode = payload
        .shell_mode
        .unwrap_or_else(|| "sftp_only".to_string());
    if !matches!(role.as_str(), "tenant" | "admin")
        || !matches!(
            shell_mode.as_str(),
            "sftp_only" | "standard_shell" | "sudo_admin"
        )
    {
        return Err((StatusCode::BAD_REQUEST, "Invalid role or shell mode".into()));
    }
    if payload
        .password
        .as_deref()
        .is_some_and(|password| password.contains(['\n', '\r', ':']))
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "Password cannot contain a newline or colon".into(),
        ));
    }

    // 1. Generate SSH Key pair (Ed25519) and password
    let mut creds = generate_credentials().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Keygen failed: {}", e),
        )
    })?;

    if let Some(custom_pw) = payload.password {
        if !custom_pw.is_empty() {
            creds.password_plain = custom_pw;
        }
    }

    // 2. Hash password for panel authentication
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(creds.password_plain.as_bytes(), &salt)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .to_string();

    // Check for an existing panel account before creating the Linux user.
    let conn = pool
        .get()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM users WHERE username = ?1)",
            [&username],
            |r| r.get(0),
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if exists {
        return Err((StatusCode::CONFLICT, "User already exists".into()));
    }

    // Provision Linux account before registering it as available in the panel.
    provision_linux_user(&username, &creds, &shell_mode).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Linux user provisioning failed: {}", e),
        )
    })?;

    conn.execute(
        "INSERT INTO users (username, password_hash, role, shell_mode, is_disabled) 
         VALUES (?1, ?2, ?3, ?4, 0)",
        rusqlite::params![&username, &password_hash, &role, &shell_mode],
    )
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("User already exists or DB error: {}", e),
        )
    })?;

    let user_id = conn.last_insert_rowid();

    conn.execute(
        "INSERT INTO ssh_credentials (user_id, public_key, private_key_pem, initial_password) 
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![
            user_id,
            &creds.public_key_openssh,
            &creds.private_key_pem,
            &creds.password_plain
        ],
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to save SSH credentials: {}", e),
        )
    })?;

    let cred_id = conn.last_insert_rowid();

    // Audit log
    let _ = conn.execute(
        "INSERT INTO audit_logs (user_id, username, action, object_type, object_id, details) 
         VALUES (?1, ?2, 'create_user', 'user', ?3, ?4)",
        rusqlite::params![
            claims.user_id,
            claims.sub,
            user_id.to_string(),
            format!("Created user {} with shell mode {}", username, shell_mode)
        ],
    );

    let user = User {
        id: user_id,
        username,
        password_hash: "".to_string(),
        role,
        shell_mode,
        is_disabled: false,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
    };

    let ssh_credentials = SshCredential {
        id: cred_id,
        user_id,
        public_key: creds.public_key_openssh,
        private_key_pem: creds.private_key_pem,
        initial_password: Some(creds.password_plain),
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
    };

    Ok(Json(UserCreatedResponse {
        user,
        ssh_credentials,
    }))
}

pub async fn get_user_credentials(
    State(pool): State<DbPool>,
    Path(user_id): Path<i64>,
    headers: HeaderMap,
    Extension(config): Extension<Arc<AppConfig>>,
) -> Result<Json<SshCredential>, (StatusCode, String)> {
    let token = extract_bearer_token(&headers)?;
    let claims = verify_jwt(&token, &config.jwt_secret)?;

    if claims.role != "admin" && claims.user_id != user_id {
        return Err((StatusCode::FORBIDDEN, "Access denied".to_string()));
    }

    let conn = pool
        .get()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let cred: SshCredential = conn
        .query_row(
            "SELECT id, user_id, public_key, private_key_pem, initial_password, created_at, updated_at 
             FROM ssh_credentials WHERE user_id = ?1",
            [user_id],
            |row| {
                Ok(SshCredential {
                    id: row.get(0)?,
                    user_id: row.get(1)?,
                    public_key: row.get(2)?,
                    private_key_pem: row.get(3)?,
                    initial_password: row.get(4)?,
                    created_at: row.get(5)?,
                    updated_at: row.get(6)?,
                })
            },
        )
        .map_err(|_| (StatusCode::NOT_FOUND, "SSH credentials not found".to_string()))?;

    Ok(Json(cred))
}

pub async fn rotate_user_ssh(
    State(pool): State<DbPool>,
    Path(user_id): Path<i64>,
    headers: HeaderMap,
    Extension(config): Extension<Arc<AppConfig>>,
) -> Result<Json<SshCredential>, (StatusCode, String)> {
    let token = extract_bearer_token(&headers)?;
    let claims = verify_jwt(&token, &config.jwt_secret)?;

    if claims.role != "admin" && claims.user_id != user_id {
        return Err((StatusCode::FORBIDDEN, "Access denied".to_string()));
    }

    let conn = pool
        .get()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let (username, shell_mode): (String, String) = conn
        .query_row(
            "SELECT username, shell_mode FROM users WHERE id = ?1",
            [user_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(|_| (StatusCode::NOT_FOUND, "User not found".to_string()))?;

    let creds = generate_credentials().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Keygen failed: {}", e),
        )
    })?;

    provision_linux_user(&username, &creds, &shell_mode).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("SSH rotation failed: {}", e),
        )
    })?;

    conn.execute(
        "UPDATE ssh_credentials 
         SET public_key = ?1, private_key_pem = ?2, initial_password = ?3, updated_at = datetime('now') 
         WHERE user_id = ?4",
        rusqlite::params![
            &creds.public_key_openssh,
            &creds.private_key_pem,
            &creds.password_plain,
            user_id
        ],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Audit log
    let _ = conn.execute(
        "INSERT INTO audit_logs (user_id, username, action, object_type, object_id, details) 
         VALUES (?1, ?2, 'rotate_ssh_key', 'user', ?3, ?4)",
        rusqlite::params![
            claims.user_id,
            claims.sub,
            user_id.to_string(),
            format!("Rotated SSH credentials for user {}", username)
        ],
    );

    let updated_cred = SshCredential {
        id: 0,
        user_id,
        public_key: creds.public_key_openssh,
        private_key_pem: creds.private_key_pem,
        initial_password: Some(creds.password_plain),
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
    };

    Ok(Json(updated_cred))
}

pub async fn delete_user(
    State(pool): State<DbPool>,
    Path(user_id): Path<i64>,
    headers: HeaderMap,
    Extension(config): Extension<Arc<AppConfig>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_bearer_token(&headers)?;
    let claims = verify_jwt(&token, &config.jwt_secret)?;

    if claims.role != "admin" {
        return Err((
            StatusCode::FORBIDDEN,
            "Only administrators can delete users".to_string(),
        ));
    }

    if user_id == claims.user_id {
        return Err((
            StatusCode::BAD_REQUEST,
            "Cannot delete your own account".to_string(),
        ));
    }

    let conn = pool
        .get()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let username: String = conn
        .query_row("SELECT username FROM users WHERE id = ?1", [user_id], |r| {
            r.get(0)
        })
        .map_err(|_| (StatusCode::NOT_FOUND, "User not found".to_string()))?;

    delete_linux_user(&username).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Linux user deletion failed: {}", e),
        )
    })?;

    conn.execute("DELETE FROM users WHERE id = ?1", [user_id])
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Audit log
    let _ = conn.execute(
        "INSERT INTO audit_logs (user_id, username, action, object_type, object_id, details) 
         VALUES (?1, ?2, 'delete_user', 'user', ?3, ?4)",
        rusqlite::params![
            claims.user_id,
            claims.sub,
            user_id.to_string(),
            format!("Deleted user {}", username)
        ],
    );

    Ok(Json(serde_json::json!({ "success": true })))
}
