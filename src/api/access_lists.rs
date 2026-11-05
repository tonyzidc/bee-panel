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
use std::{
    io::Write,
    process::{Command, Stdio},
    sync::Arc,
};

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

        let mut auth_stmt = conn.prepare(
            "SELECT id, access_list_id, username FROM access_list_auths WHERE access_list_id = ?1",
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        list.auth_users = auth_stmt
            .query_map([list.id], |row| {
                Ok(AccessListAuth {
                    id: row.get(0)?,
                    access_list_id: row.get(1)?,
                    username: row.get(2)?,
                    password_hash: String::new(),
                })
            })
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

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
        return Err((
            StatusCode::FORBIDDEN,
            "Only admin can create access lists".to_string(),
        ));
    }

    if payload.name.trim().is_empty() || payload.name.contains(['\n', '\r']) {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid access list name".to_string(),
        ));
    }
    for item in &payload.items {
        if !matches!(item.directive.as_str(), "allow" | "deny") || !valid_address(&item.address) {
            return Err((StatusCode::BAD_REQUEST, "Invalid IP rule".to_string()));
        }
    }
    for user in &payload.auth_users {
        if user.username.is_empty()
            || user.username.contains([':', '\n', '\r'])
            || user.password.is_empty()
            || user.password.contains(['\n', '\r'])
        {
            return Err((
                StatusCode::BAD_REQUEST,
                "Invalid Basic Auth credential".to_string(),
            ));
        }
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
        let hash = hash_basic_auth(&user.password)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
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
    if let Err(e) = engine.deploy_access_list(&list) {
        let _ = conn.execute("DELETE FROM access_lists WHERE id = ?1", [list_id]);
        let _ = engine.delete_access_list(list_id);
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Nginx configuration failed: {}", e),
        ));
    }

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
        return Err((
            StatusCode::FORBIDDEN,
            "Only admin can delete access lists".to_string(),
        ));
    }

    let conn = pool
        .get()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let uses: i64 = conn
        .query_row(
            "SELECT count(*) FROM proxy_hosts WHERE access_list_id = ?1",
            [list_id],
            |r| r.get(0),
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if uses > 0 {
        return Err((
            StatusCode::CONFLICT,
            "Access list is used by a proxy host".to_string(),
        ));
    }

    let engine = NginxEngine::new((*config).clone())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    engine
        .delete_access_list(list_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    conn.execute("DELETE FROM access_lists WHERE id = ?1", [list_id])
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({ "success": true })))
}

fn valid_address(value: &str) -> bool {
    if value == "all" {
        return true;
    }
    let (ip, prefix) = value
        .split_once('/')
        .map_or((value, None), |(ip, p)| (ip, Some(p)));
    let addr: std::net::IpAddr = match ip.parse() {
        Ok(addr) => addr,
        Err(_) => return false,
    };
    match prefix {
        None => true,
        Some(p) => p
            .parse::<u8>()
            .is_ok_and(|bits| bits <= if addr.is_ipv4() { 32 } else { 128 }),
    }
}

fn hash_basic_auth(password: &str) -> anyhow::Result<String> {
    let mut child = Command::new("openssl")
        .args(["passwd", "-6", "-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("OpenSSL stdin unavailable"))?
        .write_all(password.as_bytes())?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        anyhow::bail!("OpenSSL password hashing failed");
    }
    let hash = String::from_utf8(output.stdout)?.trim().to_string();
    if !hash.starts_with("$6$") {
        anyhow::bail!("Unexpected password hash format");
    }
    Ok(hash)
}
