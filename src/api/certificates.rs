use crate::api::auth::{extract_bearer_token, verify_jwt};
use crate::config::AppConfig;
use crate::core::acme::AcmeManager;
use crate::db::models::Certificate;
use crate::db::DbPool;
use axum::{
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct RequestLetsEncryptInput {
    pub domain_names: Vec<String>,
    pub contact_email: String,
    pub is_staging: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct UploadCustomCertInput {
    pub nice_name: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub intermediate_pem: Option<String>,
}

pub async fn list_certificates(
    State(pool): State<DbPool>,
    headers: HeaderMap,
    Extension(config): Extension<Arc<AppConfig>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_bearer_token(&headers)?;
    let _ = verify_jwt(&token, &config.jwt_secret)?;

    let conn = pool
        .get()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut stmt = conn
        .prepare(
            "SELECT id, provider, nice_name, domain_names, expires_at, cert_path, key_path, 
                    intermediate_path, auto_renew, is_valid, created_at, updated_at 
             FROM certificates ORDER BY id DESC",
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let rows = stmt
        .query_map([], |row| {
            let domain_json: String = row.get(3)?;
            let domain_names: Vec<String> = serde_json::from_str(&domain_json).unwrap_or_default();

            Ok(Certificate {
                id: row.get(0)?,
                provider: row.get(1)?,
                nice_name: row.get(2)?,
                domain_names,
                expires_at: row.get(4)?,
                cert_path: row.get(5)?,
                key_path: row.get(6)?,
                intermediate_path: row.get(7)?,
                auto_renew: row.get(8)?,
                is_valid: row.get(9)?,
                created_at: row.get(10)?,
                updated_at: row.get(11)?,
            })
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let certs: Vec<Certificate> = rows.filter_map(|r| r.ok()).collect();
    Ok(Json(certs))
}

pub async fn request_letsencrypt(
    State(pool): State<DbPool>,
    headers: HeaderMap,
    Extension(config): Extension<Arc<AppConfig>>,
    Json(payload): Json<RequestLetsEncryptInput>,
) -> Result<Json<Certificate>, (StatusCode, String)> {
    let token = extract_bearer_token(&headers)?;
    let claims = verify_jwt(&token, &config.jwt_secret)?;

    if payload.domain_names.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "At least one domain name is required".to_string()));
    }

    let acme = AcmeManager::new((*config).clone());
    let is_staging = payload.is_staging.unwrap_or(false);

    let issued = acme
        .issue_letsencrypt_cert(&payload.domain_names, &payload.contact_email, is_staging)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("ACME Issuance Error: {}", e)))?;

    let conn = pool
        .get()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let domains_json = serde_json::to_string(&payload.domain_names).unwrap_or_default();
    let nice_name = payload.domain_names.join(", ");

    conn.execute(
        "INSERT INTO certificates (provider, nice_name, domain_names, expires_at, cert_path, key_path, auto_renew, is_valid) 
         VALUES ('letsencrypt', ?1, ?2, ?3, '', '', 1, 1)",
        rusqlite::params![&nice_name, &domains_json, &issued.expires_at],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let cert_id = conn.last_insert_rowid();

    // Save cert and key files to disk
    let (cert_path, key_path) = acme
        .save_certificate(cert_id, &issued.cert_pem, &issued.key_pem)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    conn.execute(
        "UPDATE certificates SET cert_path = ?1, key_path = ?2 WHERE id = ?3",
        rusqlite::params![cert_path.to_str().unwrap(), key_path.to_str().unwrap(), cert_id],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Audit log
    let _ = conn.execute(
        "INSERT INTO audit_logs (user_id, username, action, object_type, object_id, details) 
         VALUES (?1, ?2, 'issue_certificate', 'certificate', ?3, ?4)",
        rusqlite::params![
            claims.user_id,
            claims.sub,
            cert_id.to_string(),
            format!("Issued Let's Encrypt certificate for {:?}", payload.domain_names)
        ],
    );

    let cert = Certificate {
        id: cert_id,
        provider: "letsencrypt".to_string(),
        nice_name,
        domain_names: payload.domain_names,
        expires_at: Some(issued.expires_at),
        cert_path: cert_path.to_str().unwrap().to_string(),
        key_path: key_path.to_str().unwrap().to_string(),
        intermediate_path: None,
        auto_renew: true,
        is_valid: true,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
    };

    Ok(Json(cert))
}

pub async fn upload_custom_cert(
    State(pool): State<DbPool>,
    headers: HeaderMap,
    Extension(config): Extension<Arc<AppConfig>>,
    Json(payload): Json<UploadCustomCertInput>,
) -> Result<Json<Certificate>, (StatusCode, String)> {
    let token = extract_bearer_token(&headers)?;
    let _claims = verify_jwt(&token, &config.jwt_secret)?;

    let conn = pool
        .get()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    conn.execute(
        "INSERT INTO certificates (provider, nice_name, domain_names, cert_path, key_path, auto_renew, is_valid) 
         VALUES ('custom', ?1, '[]', '', '', 0, 1)",
        rusqlite::params![&payload.nice_name],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let cert_id = conn.last_insert_rowid();

    let acme = AcmeManager::new((*config).clone());
    let (cert_path, key_path) = acme
        .save_certificate(cert_id, &payload.cert_pem, &payload.key_pem)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    conn.execute(
        "UPDATE certificates SET cert_path = ?1, key_path = ?2 WHERE id = ?3",
        rusqlite::params![cert_path.to_str().unwrap(), key_path.to_str().unwrap(), cert_id],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let cert = Certificate {
        id: cert_id,
        provider: "custom".to_string(),
        nice_name: payload.nice_name,
        domain_names: vec![],
        expires_at: None,
        cert_path: cert_path.to_str().unwrap().to_string(),
        key_path: key_path.to_str().unwrap().to_string(),
        intermediate_path: payload.intermediate_pem,
        auto_renew: false,
        is_valid: true,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
    };

    Ok(Json(cert))
}

pub async fn delete_certificate(
    State(pool): State<DbPool>,
    Path(cert_id): Path<i64>,
    headers: HeaderMap,
    Extension(config): Extension<Arc<AppConfig>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_bearer_token(&headers)?;
    let claims = verify_jwt(&token, &config.jwt_secret)?;

    if claims.role != "admin" {
        return Err((StatusCode::FORBIDDEN, "Access denied".to_string()));
    }

    let conn = pool
        .get()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let cert_dir = config.certs_dir.join(format!("{}", cert_id));
    let _ = std::fs::remove_dir_all(cert_dir);

    conn.execute("DELETE FROM certificates WHERE id = ?1", [cert_id])
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({ "success": true })))
}
