use crate::api::auth::{extract_bearer_token, verify_jwt};
use crate::config::AppConfig;
use crate::core::metrics::MetricsCollector;
use axum::{
    extract::Extension,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use std::sync::{Arc, Mutex};

pub async fn get_metrics(
    headers: HeaderMap,
    Extension(config): Extension<Arc<AppConfig>>,
    Extension(collector): Extension<Arc<Mutex<MetricsCollector>>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_bearer_token(&headers)?;
    let _ = verify_jwt(&token, &config.jwt_secret)?;

    let mut collector_guard = collector
        .lock()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let metrics = collector_guard.collect();
    Ok(Json(metrics))
}
