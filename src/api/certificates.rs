use crate::api::auth::{extract_bearer_token, verify_jwt};
use crate::api::validation;
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
use std::{
    io::Write,
    process::{Command, Stdio},
    sync::Arc,
};

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

    if claims.role != "admin" {
        return Err((
            StatusCode::FORBIDDEN,
            "Only administrators can issue certificates".into(),
        ));
    }
    validation::domains(&payload.domain_names)?;
    if !payload.contact_email.contains('@') || payload.contact_email.contains(['\n', '\r', ' ']) {
        return Err((StatusCode::BAD_REQUEST, "Invalid contact email".into()));
    }

    let acme = AcmeManager::new((*config).clone());
    let is_staging = payload.is_staging.unwrap_or(false);

    let issued = acme
        .issue_letsencrypt_cert(&payload.domain_names, &payload.contact_email, is_staging)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("ACME Issuance Error: {}", e),
            )
        })?;

    let conn = pool
        .get()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let domains_json = serde_json::to_string(&payload.domain_names).unwrap_or_default();
    let nice_name = payload.domain_names.join(", ");

    conn.execute(
        "INSERT INTO certificates (provider, nice_name, domain_names, expires_at, cert_path, key_path, auto_renew, is_valid, contact_email, is_staging)
         VALUES ('letsencrypt', ?1, ?2, ?3, '', '', 1, 1, ?4, ?5)",
        rusqlite::params![&nice_name, &domains_json, &issued.expires_at, &payload.contact_email, is_staging],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let cert_id = conn.last_insert_rowid();

    // Save cert and key files to disk
    let (cert_path, key_path) = acme
        .save_certificate(cert_id, &issued.cert_pem, &issued.key_pem)
        .map_err(|e| {
            let _ = conn.execute("DELETE FROM certificates WHERE id = ?1", [cert_id]);
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        })?;

    conn.execute(
        "UPDATE certificates SET cert_path = ?1, key_path = ?2 WHERE id = ?3",
        rusqlite::params![
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
            cert_id
        ],
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
            format!(
                "Issued Let's Encrypt certificate for {:?}",
                payload.domain_names
            )
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
    let claims = verify_jwt(&token, &config.jwt_secret)?;
    if claims.role != "admin" {
        return Err((
            StatusCode::FORBIDDEN,
            "Only administrators can upload certificates".into(),
        ));
    }
    if payload.nice_name.trim().is_empty()
        || !payload.cert_pem.contains("-----BEGIN CERTIFICATE-----")
        || !payload.key_pem.contains("-----BEGIN ")
        || !payload.key_pem.contains("PRIVATE KEY-----")
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid certificate or private key PEM".into(),
        ));
    }
    let cert_key = openssl(&["x509", "-pubkey", "-noout"], &payload.cert_pem)?;
    let private_key = openssl(&["pkey", "-pubout", "-passin", "pass:"], &payload.key_pem)?;
    if cert_key != private_key {
        return Err((
            StatusCode::BAD_REQUEST,
            "Certificate and private key do not match".into(),
        ));
    }
    let end_date = openssl(&["x509", "-enddate", "-noout"], &payload.cert_pem)?;
    let expires_at = end_date
        .trim()
        .strip_prefix("notAfter=")
        .and_then(|date| chrono::NaiveDateTime::parse_from_str(date, "%b %e %H:%M:%S %Y GMT").ok())
        .map(|date| date.and_utc().to_rfc3339());
    let san_text = openssl(
        &["x509", "-ext", "subjectAltName", "-noout"],
        &payload.cert_pem,
    )
    .unwrap_or_default();
    let domain_names: Vec<String> = san_text
        .split("DNS:")
        .skip(1)
        .map(|part| {
            part.split([',', '\n'])
                .next()
                .unwrap_or("")
                .trim()
                .to_string()
        })
        .filter(|domain| !domain.is_empty())
        .collect();
    let domains_json = serde_json::to_string(&domain_names)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let conn = pool
        .get()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    conn.execute(
        "INSERT INTO certificates (provider, nice_name, domain_names, expires_at, cert_path, key_path, auto_renew, is_valid)
         VALUES ('custom', ?1, ?2, ?3, '', '', 0, 1)",
        rusqlite::params![&payload.nice_name, &domains_json, &expires_at],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let cert_id = conn.last_insert_rowid();

    let acme = AcmeManager::new((*config).clone());
    let fullchain = match payload.intermediate_pem.as_deref() {
        Some(intermediate) if !intermediate.trim().is_empty() => {
            format!("{}\n{}", payload.cert_pem.trim(), intermediate.trim())
        }
        _ => payload.cert_pem.clone(),
    };
    let (cert_path, key_path) = acme
        .save_certificate(cert_id, &fullchain, &payload.key_pem)
        .map_err(|e| {
            let _ = conn.execute("DELETE FROM certificates WHERE id = ?1", [cert_id]);
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        })?;

    conn.execute(
        "UPDATE certificates SET cert_path = ?1, key_path = ?2 WHERE id = ?3",
        rusqlite::params![
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
            cert_id
        ],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let cert = Certificate {
        id: cert_id,
        provider: "custom".to_string(),
        nice_name: payload.nice_name,
        domain_names,
        expires_at,
        cert_path: cert_path.to_str().unwrap().to_string(),
        key_path: key_path.to_str().unwrap().to_string(),
        intermediate_path: None,
        auto_renew: false,
        is_valid: true,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
    };

    Ok(Json(cert))
}

fn openssl(args: &[&str], input: &str) -> Result<String, (StatusCode, String)> {
    let mut child = Command::new("openssl")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    child
        .stdin
        .take()
        .ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "OpenSSL stdin unavailable".into(),
        ))?
        .write_all(input.as_bytes())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let output = child
        .wait_with_output()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if !output.status.success() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid certificate or private key".into(),
        ));
    }
    String::from_utf8(output.stdout).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))
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

    let uses: i64 = conn
        .query_row(
            "SELECT (SELECT count(*) FROM proxy_hosts WHERE ssl_certificate_id = ?1)
              + (SELECT count(*) FROM redirection_hosts WHERE ssl_certificate_id = ?1)
              + (SELECT count(*) FROM dead_hosts WHERE ssl_certificate_id = ?1)",
            [cert_id],
            |r| r.get(0),
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if uses > 0 {
        return Err((StatusCode::CONFLICT, "Certificate is used by a host".into()));
    }

    conn.execute("DELETE FROM certificates WHERE id = ?1", [cert_id])
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let cert_dir = config.certs_dir.join(format!("{}", cert_id));
    let _ = std::fs::remove_dir_all(cert_dir);

    Ok(Json(serde_json::json!({ "success": true })))
}

pub async fn renew_due_certificates(pool: &DbPool, config: &AppConfig) -> anyhow::Result<()> {
    let due: Vec<(i64, Vec<String>, String, bool)> = {
        let conn = pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT id, domain_names, contact_email, is_staging FROM certificates
             WHERE provider = 'letsencrypt' AND auto_renew = 1 AND contact_email IS NOT NULL
               AND datetime(expires_at) <= datetime('now', '+30 days')",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, bool>(3)?,
            ))
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter_map(|(id, json, email, staging)| {
                serde_json::from_str::<Vec<String>>(&json)
                    .ok()
                    .map(|domains| (id, domains, email, staging))
            })
            .collect()
    };
    let acme = AcmeManager::new(config.clone());
    for (id, domains, email, staging) in due {
        match acme.issue_letsencrypt_cert(&domains, &email, staging).await {
            Ok(issued) => match acme.save_certificate(id, &issued.cert_pem, &issued.key_pem) {
                Ok(_) => {
                    let conn = pool.get()?;
                    conn.execute("UPDATE certificates SET expires_at = ?1, is_valid = 1, updated_at = datetime('now') WHERE id = ?2",
                        rusqlite::params![issued.expires_at, id])?;
                    tracing::info!("Renewed certificate {}", id);
                }
                Err(error) => {
                    tracing::error!("Could not save renewed certificate {}: {}", id, error)
                }
            },
            Err(error) => tracing::error!("Could not renew certificate {}: {}", id, error),
        }
    }
    Ok(())
}
