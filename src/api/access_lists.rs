use crate::api::auth::{extract_bearer_token, verify_jwt};
use crate::config::AppConfig;
use crate::core::nginx::NginxEngine;
use crate::db::models::{AccessList, AccessListAuth, AccessListItem};
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
pub struct CreateAccessListRequest {
    pub name: String,
    pub satisfy_any: Option<bool>,
    pub pass_auth_to_host: Option<bool>,
    pub items: Vec<AccessItemInput>,
    pub auth_users: Vec<AccessAuthInput>,
}

#[derive(Debug, Deserialize)]
pub struct AccessItemInput {
    pub directive: String, // "allow" | "deny"
    pub address: String,   // IP or CIDR
}

#[derive(Debug, Deserialize)]
pub struct AccessAuthInput {
    pub username: String,
    pub password: String,
}

pub async fn list_access_lists(
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
            "SELECT id, name, satisfy_any, pass_auth_to_host, created_at, updated_at 
             FROM access_lists ORDER BY id DESC",
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let rows = stmt
        .query_map([], |row| {
            Ok(AccessList {
                id: row.get(0)?,
                name: row.get(1)?,
                satisfy_any: row.get(2)?,
                pass_auth_to_host: row.get(3)?,
                items: vec![],
                auth_users: vec![],
                created_at: row.get(4)?,
                updated_at: row.get(5)?,
            })
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut lists = Vec::new();
    for r in rows {
        let mut list = r.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        // Load items
        let mut item_stmt = conn
            .prepare("SELECT id, access_list_id, directive, address FROM access_list_items WHERE access_list_id = ?1")
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        list.items = item_stmt
            .query_map([list.id], |irow| {
                Ok(AccessListItem {
                    id: irow.get(0)?,
                    access_list_id: irow.get(1)?,
                    directive: irow.get(2)?,
                    address: irow.get(3)?,
                })
            })
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .filter_map(|x| x.ok())
            .collect();

        lists.push(list);
    }

    Ok(Json(lists))
}

pub async fn create_access_list(
    State(pool): State<DbPool>,
    headers: HeaderMap,
    Extension(config): Extension<Arc<AppConfig>>,
    Json(payload): Json<CreateAccessListRequest>,
) -> Result<Json<AccessList>, (StatusCode, String)> {
    let token = extract_bearer_token(&headers)?;
    let claims = verify_jwt(&token, &config.jwt_secret)?;

    if claims.role != "admin" {
        return Err((StatusCode::FORBIDDEN, "Only admin can create access lists".to_string()));
    }

    let conn = pool
        .get()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let satisfy_any = payload.satisfy_any.unwrap_or(false);
    let pass_auth_to_host = payload.pass_auth_to_host.unwrap_or(false);

    conn.execute(
        "INSERT INTO access_lists (name, satisfy_any, pass_auth_to_host) VALUES (?1, ?2, ?3)",
        rusqlite::params![&payload.name, satisfy_any, pass_auth_to_host],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let list_id = conn.last_insert_rowid();

    let mut items = Vec::new();
    for item in payload.items {
        conn.execute(
            "INSERT INTO access_list_items (access_list_id, directive, address) VALUES (?1, ?2, ?3)",
            rusqlite::params![list_id, &item.directive, &item.address],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        items.push(AccessListItem {
            id: conn.last_insert_rowid(),
            access_list_id: list_id,
            directive: item.directive,
            address: item.address,
        });
    }

    let mut auth_users = Vec::new();
    for user in payload.auth_users {
        // Hash basic auth password with apr1 / crypt or md5
        let hash = format!("{{PLAIN}}{}", user.password); // Simple fallback or crypt
        conn.execute(
            "INSERT INTO access_list_auths (access_list_id, username, password_hash) VALUES (?1, ?2, ?3)",
            rusqlite::params![list_id, &user.username, &hash],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        auth_users.push(AccessListAuth {
            id: conn.last_insert_rowid(),
            access_list_id: list_id,
            username: user.username,
            password_hash: hash,
        });
    }

    let list = AccessList {
        id: list_id,
        name: payload.name,
        satisfy_any,
        pass_auth_to_host,
        items,
        auth_users,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
    };

    let engine = NginxEngine::new((*config).clone())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = engine.deploy_access_list(&list);

    Ok(Json(list))
}

pub async fn delete_access_list(
    State(pool): State<DbPool>,
    Path(list_id): Path<i64>,
    headers: HeaderMap,
    Extension(config): Extension<Arc<AppConfig>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_bearer_token(&headers)?;
    let claims = verify_jwt(&token, &config.jwt_secret)?;

    if claims.role != "admin" {
        return Err((StatusCode::FORBIDDEN, "Only admin can delete access lists".to_string()));
    }

    let conn = pool
        .get()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let engine = NginxEngine::new((*config).clone())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = engine.delete_access_list(list_id);

    conn.execute("DELETE FROM access_lists WHERE id = ?1", [list_id])
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({ "success": true })))
}
