use crate::api::auth::{extract_bearer_token, verify_jwt};
use crate::config::AppConfig;
use crate::db::models::AuditLog;
use crate::db::DbPool;
use axum::{
    extract::{Extension, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use std::sync::Arc;

pub async fn list_audit_logs(
    State(pool): State<DbPool>,
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

    let mut stmt = conn
        .prepare(
            "SELECT id, user_id, username, action, object_type, object_id, details, ip_address, created_at 
             FROM audit_logs ORDER BY id DESC LIMIT 100",
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let rows = stmt
        .query_map([], |row| {
            Ok(AuditLog {
                id: row.get(0)?,
                user_id: row.get(1)?,
                username: row.get(2)?,
                action: row.get(3)?,
                object_type: row.get(4)?,
                object_id: row.get(5)?,
                details: row.get(6)?,
                ip_address: row.get(7)?,
                created_at: row.get(8)?,
            })
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let logs: Vec<AuditLog> = rows.filter_map(|r| r.ok()).collect();
    Ok(Json(logs))
}
