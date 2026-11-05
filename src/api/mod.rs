pub mod access_lists;
pub mod audit;
pub mod auth;
pub mod certificates;
pub mod dead_hosts;
pub mod metrics;
pub mod proxy_hosts;
pub mod redirections;
pub mod streams;
pub mod users;

use crate::db::DbPool;
use axum::{
    routing::{delete, get, post},
    Router,
};

pub fn create_api_router(pool: DbPool) -> Router {
    Router::new()
        // Auth
        .route("/api/v2/auth/login", post(auth::login))
        .route("/api/v2/auth/me", get(auth::get_me))
        // Users & OS SSH Provisioning
        .route("/api/v2/users", get(users::list_users).post(users::create_user))
        .route("/api/v2/users/:id/credentials", get(users::get_user_credentials))
        .route("/api/v2/users/:id/rotate-ssh", post(users::rotate_user_ssh))
        .route("/api/v2/users/:id", delete(users::delete_user))
        // Proxy Hosts
        .route(
            "/api/v2/proxy-hosts",
            get(proxy_hosts::list_proxy_hosts).post(proxy_hosts::create_proxy_host),
        )
        .route("/api/v2/proxy-hosts/:id", delete(proxy_hosts::delete_proxy_host))
        // Redirection Hosts
        .route(
            "/api/v2/redirections",
            get(redirections::list_redirections).post(redirections::create_redirection),
        )
        .route("/api/v2/redirections/:id", delete(redirections::delete_redirection))
        // Streams (TCP / UDP)
        .route(
            "/api/v2/streams",
            get(streams::list_streams).post(streams::create_stream),
        )
        .route("/api/v2/streams/:id", delete(streams::delete_stream))
        // Dead Hosts (404)
        .route(
            "/api/v2/dead-hosts",
            get(dead_hosts::list_dead_hosts).post(dead_hosts::create_dead_host),
        )
        .route("/api/v2/dead-hosts/:id", delete(dead_hosts::delete_dead_host))
        // Access Lists
        .route(
            "/api/v2/access-lists",
            get(access_lists::list_access_lists).post(access_lists::create_access_list),
        )
        .route("/api/v2/access-lists/:id", delete(access_lists::delete_access_list))
        // Certificates
        .route("/api/v2/certificates", get(certificates::list_certificates))
        .route(
            "/api/v2/certificates/letsencrypt",
            post(certificates::request_letsencrypt),
        )
        .route(
            "/api/v2/certificates/custom",
            post(certificates::upload_custom_cert),
        )
        .route("/api/v2/certificates/:id", delete(certificates::delete_certificate))
        // System Metrics & Audit
        .route("/api/v2/metrics", get(metrics::get_metrics))
        .route("/api/v2/audit-logs", get(audit::list_audit_logs))
        .with_state(pool)
}
