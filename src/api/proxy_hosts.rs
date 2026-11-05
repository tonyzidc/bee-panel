use crate::api::auth::{extract_bearer_token, verify_jwt};
use crate::config::AppConfig;
use crate::core::nginx::NginxEngine;
use crate::db::models::{CustomLocation, ProxyHost};
use crate::db::DbPool;
use axum::{
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct CreateProxyHostRequest {
    pub domain_names: Vec<String>,
    pub forward_scheme: Option<String>,
    pub forward_host: String,
    pub forward_port: u16,
    pub caching_enabled: Option<bool>,
    pub block_exploits: Option<bool>,
    pub websocket_support: Option<bool>,
    pub ssl_certificate_id: Option<i64>,
    pub ssl_forced: Option<bool>,
    pub http2_support: Option<bool>,
    pub hsts_enabled: Option<bool>,
    pub hsts_subdomains: Option<bool>,
    pub access_list_id: Option<i64>,
    pub advanced_config: Option<String>,
    pub custom_locations: Option<Vec<CustomLocationInput>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CustomLocationInput {
    pub path: String,
    pub forward_scheme: Option<String>,
    pub forward_host: String,
    pub forward_port: u16,
    pub advanced_config: Option<String>,
}

pub async fn list_proxy_hosts(
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
            "SELECT id, user_id, domain_names, forward_scheme, forward_host, forward_port, 
                    caching_enabled, block_exploits, websocket_support, ssl_certificate_id, 
                    ssl_forced, http2_support, hsts_enabled, hsts_subdomains, access_list_id, 
                    advanced_config, is_enabled, created_at, updated_at 
             FROM proxy_hosts ORDER BY id DESC",
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let rows = stmt
        .query_map([], |row| {
            let domain_json: String = row.get(2)?;
            let domain_names: Vec<String> = serde_json::from_str(&domain_json).unwrap_or_default();

            Ok(ProxyHost {
                id: row.get(0)?,
                user_id: row.get(1)?,
                domain_names,
                forward_scheme: row.get(3)?,
                forward_host: row.get(4)?,
                forward_port: row.get(5)?,
                caching_enabled: row.get(6)?,
                block_exploits: row.get(7)?,
                websocket_support: row.get(8)?,
                ssl_certificate_id: row.get(9)?,
                ssl_forced: row.get(10)?,
                http2_support: row.get(11)?,
                hsts_enabled: row.get(12)?,
                hsts_subdomains: row.get(13)?,
                access_list_id: row.get(14)?,
                advanced_config: row.get(15)?,
                is_enabled: row.get(16)?,
                custom_locations: vec![],
                created_at: row.get(17)?,
                updated_at: row.get(18)?,
            })
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut list = Vec::new();
    for r in rows {
        let mut host = r.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if claims.role != "admin" && host.user_id != claims.user_id {
            continue;
        }

        // Fetch custom locations
        let mut loc_stmt = conn
            .prepare(
                "SELECT id, proxy_host_id, path, forward_scheme, forward_host, forward_port, advanced_config 
                 FROM custom_locations WHERE proxy_host_id = ?1",
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let locs: Vec<CustomLocation> = loc_stmt
            .query_map([host.id], |lrow| {
                Ok(CustomLocation {
                    id: lrow.get(0)?,
                    proxy_host_id: lrow.get(1)?,
                    path: lrow.get(2)?,
                    forward_scheme: lrow.get(3)?,
                    forward_host: lrow.get(4)?,
                    forward_port: lrow.get(5)?,
                    advanced_config: lrow.get(6)?,
                })
            })
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .filter_map(|x| x.ok())
            .collect();

        host.custom_locations = locs;
        list.push(host);
    }

    Ok(Json(list))
}

pub async fn create_proxy_host(
    State(pool): State<DbPool>,
    headers: HeaderMap,
    Extension(config): Extension<Arc<AppConfig>>,
    Json(payload): Json<CreateProxyHostRequest>,
) -> Result<Json<ProxyHost>, (StatusCode, String)> {
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

    let forward_scheme = payload.forward_scheme.unwrap_or_else(|| "http".to_string());
    let caching_enabled = payload.caching_enabled.unwrap_or(false);
    let block_exploits = payload.block_exploits.unwrap_or(true);
    let websocket_support = payload.websocket_support.unwrap_or(true);
    let ssl_forced = payload.ssl_forced.unwrap_or(false);
    let http2_support = payload.http2_support.unwrap_or(true);
    let hsts_enabled = payload.hsts_enabled.unwrap_or(false);
    let hsts_subdomains = payload.hsts_subdomains.unwrap_or(false);

    conn.execute(
        "INSERT INTO proxy_hosts (
            user_id, domain_names, forward_scheme, forward_host, forward_port, 
            caching_enabled, block_exploits, websocket_support, ssl_certificate_id, 
            ssl_forced, http2_support, hsts_enabled, hsts_subdomains, access_list_id, 
            advanced_config, is_enabled
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, 1)",
        rusqlite::params![
            claims.user_id,
            &domains_json,
            &forward_scheme,
            &payload.forward_host,
            payload.forward_port,
            caching_enabled,
            block_exploits,
            websocket_support,
            payload.ssl_certificate_id,
            ssl_forced,
            http2_support,
            hsts_enabled,
            hsts_subdomains,
            payload.access_list_id,
            &payload.advanced_config,
        ],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB insert error: {}", e)))?;

    let host_id = conn.last_insert_rowid();

    // Insert custom locations
    let mut custom_locations = Vec::new();
    if let Some(locs) = payload.custom_locations {
        for loc in locs {
            let l_scheme = loc.forward_scheme.unwrap_or_else(|| "http".to_string());
            conn.execute(
                "INSERT INTO custom_locations (proxy_host_id, path, forward_scheme, forward_host, forward_port, advanced_config) 
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    host_id,
                    &loc.path,
                    &l_scheme,
                    &loc.forward_host,
                    loc.forward_port,
                    &loc.advanced_config,
                ],
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

            custom_locations.push(CustomLocation {
                id: conn.last_insert_rowid(),
                proxy_host_id: host_id,
                path: loc.path,
                forward_scheme: l_scheme,
                forward_host: loc.forward_host,
                forward_port: loc.forward_port,
                advanced_config: loc.advanced_config,
            });
        }
    }

    // SSL lookup
    let mut ssl_cert_paths = None;
    if let Some(cert_id) = payload.ssl_certificate_id {
        let cert_info: Result<(String, String), _> = conn.query_row(
            "SELECT cert_path, key_path FROM certificates WHERE id = ?1",
            [cert_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        );
        if let Ok((c, k)) = cert_info {
            ssl_cert_paths = Some((c, k));
        }
    }

    let host = ProxyHost {
        id: host_id,
        user_id: claims.user_id,
        domain_names: payload.domain_names,
        forward_scheme,
        forward_host: payload.forward_host,
        forward_port: payload.forward_port,
        caching_enabled,
        block_exploits,
        websocket_support,
        ssl_certificate_id: payload.ssl_certificate_id,
        ssl_forced,
        http2_support,
        hsts_enabled,
        hsts_subdomains,
        access_list_id: payload.access_list_id,
        advanced_config: payload.advanced_config,
        is_enabled: true,
        custom_locations,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
    };

    // Deploy to Nginx native
    let engine = NginxEngine::new((*config).clone())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let cert_ref = ssl_cert_paths
        .as_ref()
        .map(|(c, k)| (c.as_str(), k.as_str()));

    if let Err(e) = engine.deploy_proxy_host(&host, cert_ref) {
        // Rollback DB if Nginx configuration failed
        let _ = conn.execute("DELETE FROM proxy_hosts WHERE id = ?1", [host_id]);
        return Err((StatusCode::BAD_REQUEST, format!("Nginx configuration failed: {}", e)));
    }

    // Audit log
    let _ = conn.execute(
        "INSERT INTO audit_logs (user_id, username, action, object_type, object_id, details) 
         VALUES (?1, ?2, 'create_proxy_host', 'proxy_host', ?3, ?4)",
        rusqlite::params![
            claims.user_id,
            claims.sub,
            host_id.to_string(),
            format!("Created proxy host for domains: {:?}", host.domain_names)
        ],
    );

    Ok(Json(host))
}

pub async fn delete_proxy_host(
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

    let (user_id, domains): (i64, String) = conn
        .query_row(
            "SELECT user_id, domain_names FROM proxy_hosts WHERE id = ?1",
            [host_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(|_| (StatusCode::NOT_FOUND, "Proxy host not found".to_string()))?;

    if claims.role != "admin" && claims.user_id != user_id {
        return Err((StatusCode::FORBIDDEN, "Access denied".to_string()));
    }

    // Delete from Nginx
    let engine = NginxEngine::new((*config).clone())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = engine.delete_proxy_host(host_id);

    // Delete from DB
    conn.execute("DELETE FROM proxy_hosts WHERE id = ?1", [host_id])
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Audit log
    let _ = conn.execute(
        "INSERT INTO audit_logs (user_id, username, action, object_type, object_id, details) 
         VALUES (?1, ?2, 'delete_proxy_host', 'proxy_host', ?3, ?4)",
        rusqlite::params![
            claims.user_id,
            claims.sub,
            host_id.to_string(),
            format!("Deleted proxy host {}", domains)
        ],
    );

    Ok(Json(serde_json::json!({ "success": true })))
}
