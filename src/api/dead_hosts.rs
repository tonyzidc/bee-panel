use crate::api::auth::{extract_bearer_token, verify_jwt};
use crate::config::AppConfig;
use crate::core::nginx::NginxEngine;
use crate::db::models::DeadHost;
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
pub struct CreateDeadHostRequest {
    pub domain_names: Vec<String>,
    pub status_code: Option<u16>,
    pub custom_message: Option<String>,
    pub ssl_certificate_id: Option<i64>,
}

pub async fn list_dead_hosts(
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
            "SELECT id, user_id, domain_names, status_code, custom_message, ssl_certificate_id, 
                    is_enabled, created_at, updated_at 
             FROM dead_hosts ORDER BY id DESC",
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let rows = stmt
        .query_map([], |row| {
            let domain_json: String = row.get(2)?;
            let domain_names: Vec<String> = serde_json::from_str(&domain_json).unwrap_or_default();

            Ok(DeadHost {
                id: row.get(0)?,
                user_id: row.get(1)?,
                domain_names,
                status_code: row.get(3)?,
                custom_message: row.get(4)?,
                ssl_certificate_id: row.get(5)?,
                is_enabled: row.get(6)?,
                created_at: row.get(7)?,
                updated_at: row.get(8)?,
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

pub async fn create_dead_host(
    State(pool): State<DbPool>,
    headers: HeaderMap,
    Extension(config): Extension<Arc<AppConfig>>,
    Json(payload): Json<CreateDeadHostRequest>,
) -> Result<Json<DeadHost>, (StatusCode, String)> {
    let token = extract_bearer_token(&headers)?;
    let claims = verify_jwt(&token, &config.jwt_secret)?;

    if payload.domain_names.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Domain names cannot be empty".to_string()));
    }

    let conn = pool
        .get()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let domains_json = serde_json::to_string(&payload.domain_names)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let status_code = payload.status_code.unwrap_or(404);

    conn.execute(
        "INSERT INTO dead_hosts (
            user_id, domain_names, status_code, custom_message, ssl_certificate_id, is_enabled
        ) VALUES (?1, ?2, ?3, ?4, ?5, 1)",
        rusqlite::params![
            claims.user_id,
            &domains_json,
            status_code,
            &payload.custom_message,
            payload.ssl_certificate_id,
        ],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB insert error: {}", e)))?;

    let host_id = conn.last_insert_rowid();

    let host = DeadHost {
        id: host_id,
        user_id: claims.user_id,
        domain_names: payload.domain_names,
        status_code,
        custom_message: payload.custom_message,
        ssl_certificate_id: payload.ssl_certificate_id,
        is_enabled: true,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
    };

    let engine = NginxEngine::new((*config).clone())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if let Err(e) = engine.deploy_dead_host(&host, None) {
        let _ = conn.execute("DELETE FROM dead_hosts WHERE id = ?1", [host_id]);
        return Err((StatusCode::BAD_REQUEST, format!("Nginx dead host error: {}", e)));
    }

    Ok(Json(host))
}

pub async fn delete_dead_host(
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
        .query_row("SELECT user_id FROM dead_hosts WHERE id = ?1", [host_id], |r| r.get(0))
        .map_err(|_| (StatusCode::NOT_FOUND, "Dead host not found".to_string()))?;

    if claims.role != "admin" && claims.user_id != user_id {
        return Err((StatusCode::FORBIDDEN, "Access denied".to_string()));
    }

    let engine = NginxEngine::new((*config).clone())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = engine.delete_dead_host(host_id);

    conn.execute("DELETE FROM dead_hosts WHERE id = ?1", [host_id])
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({ "success": true })))
}
