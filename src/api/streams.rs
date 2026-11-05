use crate::api::auth::{extract_bearer_token, verify_jwt};
use crate::api::validation;
use crate::config::AppConfig;
use crate::core::nginx::NginxEngine;
use crate::db::models::StreamHost;
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
pub struct CreateStreamRequest {
    pub incoming_port: u16,
    pub forward_host: String,
    pub forward_port: u16,
    pub tcp_forwarding: Option<bool>,
    pub udp_forwarding: Option<bool>,
}

pub async fn list_streams(
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
            "SELECT id, user_id, incoming_port, forward_host, forward_port, tcp_forwarding, 
                    udp_forwarding, is_enabled, created_at, updated_at 
             FROM stream_hosts ORDER BY id DESC",
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let rows = stmt
        .query_map([], |row| {
            Ok(StreamHost {
                id: row.get(0)?,
                user_id: row.get(1)?,
                incoming_port: row.get(2)?,
                forward_host: row.get(3)?,
                forward_port: row.get(4)?,
                tcp_forwarding: row.get(5)?,
                udp_forwarding: row.get(6)?,
                is_enabled: row.get(7)?,
                created_at: row.get(8)?,
                updated_at: row.get(9)?,
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

pub async fn create_stream(
    State(pool): State<DbPool>,
    headers: HeaderMap,
    Extension(config): Extension<Arc<AppConfig>>,
    Json(payload): Json<CreateStreamRequest>,
) -> Result<Json<StreamHost>, (StatusCode, String)> {
    let token = extract_bearer_token(&headers)?;
    let claims = verify_jwt(&token, &config.jwt_secret)?;

    validation::port(payload.incoming_port)?;
    validation::port(payload.forward_port)?;
    if !validation::upstream_host(&payload.forward_host) {
        return Err((StatusCode::BAD_REQUEST, "Invalid forward host".into()));
    }
    if !payload.tcp_forwarding.unwrap_or(true) && !payload.udp_forwarding.unwrap_or(false) {
        return Err((
            StatusCode::BAD_REQUEST,
            "Select TCP or UDP forwarding".into(),
        ));
    }

    let conn = pool
        .get()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let tcp_forwarding = payload.tcp_forwarding.unwrap_or(true);
    let udp_forwarding = payload.udp_forwarding.unwrap_or(false);

    conn.execute(
        "INSERT INTO stream_hosts (
            user_id, incoming_port, forward_host, forward_port, tcp_forwarding, udp_forwarding, is_enabled
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1)",
        rusqlite::params![
            claims.user_id,
            payload.incoming_port,
            &payload.forward_host,
            payload.forward_port,
            tcp_forwarding,
            udp_forwarding,
        ],
    )
    .map_err(|e| (StatusCode::BAD_REQUEST, format!("Port already in use or DB error: {}", e)))?;

    let host_id = conn.last_insert_rowid();

    let host = StreamHost {
        id: host_id,
        user_id: claims.user_id,
        incoming_port: payload.incoming_port,
        forward_host: payload.forward_host,
        forward_port: payload.forward_port,
        tcp_forwarding,
        udp_forwarding,
        is_enabled: true,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
    };

    let engine = NginxEngine::new((*config).clone())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if let Err(e) = engine.deploy_stream(&host) {
        let _ = conn.execute("DELETE FROM stream_hosts WHERE id = ?1", [host_id]);
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Nginx stream error: {}", e),
        ));
    }

    Ok(Json(host))
}

pub async fn delete_stream(
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
            "SELECT user_id FROM stream_hosts WHERE id = ?1",
            [host_id],
            |r| r.get(0),
        )
        .map_err(|_| (StatusCode::NOT_FOUND, "Stream not found".to_string()))?;

    if claims.role != "admin" && claims.user_id != user_id {
        return Err((StatusCode::FORBIDDEN, "Access denied".to_string()));
    }

    let engine = NginxEngine::new((*config).clone())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    engine
        .delete_stream(host_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    conn.execute("DELETE FROM stream_hosts WHERE id = ?1", [host_id])
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({ "success": true })))
}
