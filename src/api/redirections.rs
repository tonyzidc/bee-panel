use crate::api::auth::{extract_bearer_token, verify_jwt};
use crate::api::validation;
use crate::config::AppConfig;
use crate::core::nginx::NginxEngine;
use crate::db::models::RedirectionHost;
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
pub struct CreateRedirectionRequest {
    pub domain_names: Vec<String>,
    pub forward_http_code: Option<u16>,
    pub forward_scheme: Option<String>,
    pub forward_domain: String,
    pub preserve_path: Option<bool>,
    pub block_exploits: Option<bool>,
    pub ssl_certificate_id: Option<i64>,
}

pub async fn list_redirections(
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
            "SELECT id, user_id, domain_names, forward_http_code, forward_scheme, forward_domain, 
                    preserve_path, block_exploits, ssl_certificate_id, is_enabled, created_at, updated_at 
             FROM redirection_hosts ORDER BY id DESC",
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let rows = stmt
        .query_map([], |row| {
            let domain_json: String = row.get(2)?;
            let domain_names: Vec<String> = serde_json::from_str(&domain_json).unwrap_or_default();

            Ok(RedirectionHost {
                id: row.get(0)?,
                user_id: row.get(1)?,
                domain_names,
                forward_http_code: row.get(3)?,
                forward_scheme: row.get(4)?,
                forward_domain: row.get(5)?,
                preserve_path: row.get(6)?,
                block_exploits: row.get(7)?,
                ssl_certificate_id: row.get(8)?,
                is_enabled: row.get(9)?,
                created_at: row.get(10)?,
                updated_at: row.get(11)?,
            })
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut list = Vec::new();
    for r in rows {
        let host = r.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if claims.role != "admin" && host.user_id != claims.user_id {
            continue;
        }
        list.push(host);
    }

    Ok(Json(list))
}

pub async fn create_redirection(
    State(pool): State<DbPool>,
    headers: HeaderMap,
    Extension(config): Extension<Arc<AppConfig>>,
    Json(payload): Json<CreateRedirectionRequest>,
) -> Result<Json<RedirectionHost>, (StatusCode, String)> {
    let token = extract_bearer_token(&headers)?;
    let claims = verify_jwt(&token, &config.jwt_secret)?;

    validation::domains(&payload.domain_names)?;
    if !validation::destination(&payload.forward_domain) {
        return Err((StatusCode::BAD_REQUEST, "Invalid destination domain".into()));
    }
    validation::scheme(payload.forward_scheme.as_deref().unwrap_or("https"))?;
    if !matches!(
        payload.forward_http_code.unwrap_or(301),
        301 | 302 | 307 | 308
    ) {
        return Err((StatusCode::BAD_REQUEST, "Invalid redirect status".into()));
    }

    let conn = pool
        .get()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let domains_json = serde_json::to_string(&payload.domain_names)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let forward_http_code = payload.forward_http_code.unwrap_or(301);
    let forward_scheme = payload
        .forward_scheme
        .unwrap_or_else(|| "https".to_string());
    let preserve_path = payload.preserve_path.unwrap_or(true);
    let block_exploits = payload.block_exploits.unwrap_or(true);

    conn.execute(
        "INSERT INTO redirection_hosts (
            user_id, domain_names, forward_http_code, forward_scheme, forward_domain, 
            preserve_path, block_exploits, ssl_certificate_id, is_enabled
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1)",
        rusqlite::params![
            claims.user_id,
            &domains_json,
            forward_http_code,
            &forward_scheme,
            &payload.forward_domain,
            preserve_path,
            block_exploits,
            payload.ssl_certificate_id,
        ],
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("DB insert error: {}", e),
        )
    })?;

    let host_id = conn.last_insert_rowid();

    let host = RedirectionHost {
        id: host_id,
        user_id: claims.user_id,
        domain_names: payload.domain_names,
        forward_http_code,
        forward_scheme,
        forward_domain: payload.forward_domain,
        preserve_path,
        block_exploits,
        ssl_certificate_id: payload.ssl_certificate_id,
        is_enabled: true,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
    };

    let cert_paths: Option<(String, String)> = match payload.ssl_certificate_id {
        Some(id) => Some(
            conn.query_row(
                "SELECT cert_path, key_path FROM certificates WHERE id = ?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| {
                let _ = conn.execute("DELETE FROM redirection_hosts WHERE id = ?1", [host_id]);
                (StatusCode::BAD_REQUEST, "Certificate not found".to_string())
            })?,
        ),
        None => None,
    };

    // Deploy to Nginx
    let engine = NginxEngine::new((*config).clone())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if let Err(e) = engine.deploy_redirection(
        &host,
        cert_paths.as_ref().map(|(c, k)| (c.as_str(), k.as_str())),
    ) {
        let _ = conn.execute("DELETE FROM redirection_hosts WHERE id = ?1", [host_id]);
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Nginx deployment failed: {}", e),
        ));
    }

    Ok(Json(host))
}

pub async fn delete_redirection(
    State(pool): State<DbPool>,
    Path(host_id): Path<i64>,
    headers: HeaderMap,
    Extension(config): Extension<Arc<AppConfig>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_bearer_token(&headers)?;
    let claims = verify_jwt(&token, &config.jwt_secret)?;

    let conn = pool
        .get()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let user_id: i64 = conn
        .query_row(
            "SELECT user_id FROM redirection_hosts WHERE id = ?1",
            [host_id],
            |r| r.get(0),
        )
        .map_err(|_| {
            (
                StatusCode::NOT_FOUND,
                "Redirection host not found".to_string(),
            )
        })?;

    if claims.role != "admin" && claims.user_id != user_id {
        return Err((StatusCode::FORBIDDEN, "Access denied".to_string()));
    }

    let engine = NginxEngine::new((*config).clone())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    engine
        .delete_redirection(host_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    conn.execute("DELETE FROM redirection_hosts WHERE id = ?1", [host_id])
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({ "success": true })))
}
