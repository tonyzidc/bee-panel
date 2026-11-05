use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    #[allow(dead_code)]
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub role: String,       // "admin" | "tenant"
    pub shell_mode: String, // "sftp_only" | "standard_shell" | "sudo_admin"
    pub is_disabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshCredential {
    pub id: i64,
    pub user_id: i64,
    pub public_key: String,
    pub private_key_pem: String,
    pub initial_password: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomLocation {
    pub id: i64,
    pub proxy_host_id: i64,
    pub path: String,
    pub forward_scheme: String,
    pub forward_host: String,
    pub forward_port: u16,
    pub advanced_config: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyHost {
    pub id: i64,
    pub user_id: i64,
    pub domain_names: Vec<String>,
    pub forward_scheme: String,
    pub forward_host: String,
    pub forward_port: u16,
    pub caching_enabled: bool,
    pub block_exploits: bool,
    pub websocket_support: bool,
    pub ssl_certificate_id: Option<i64>,
    pub ssl_forced: bool,
    pub http2_support: bool,
    pub hsts_enabled: bool,
    pub hsts_subdomains: bool,
    pub access_list_id: Option<i64>,
    pub pass_auth_to_host: bool,
    pub advanced_config: Option<String>,
    pub is_enabled: bool,
    pub custom_locations: Vec<CustomLocation>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectionHost {
    pub id: i64,
    pub user_id: i64,
    pub domain_names: Vec<String>,
    pub forward_http_code: u16,
    pub forward_scheme: String,
    pub forward_domain: String,
    pub preserve_path: bool,
    pub block_exploits: bool,
    pub ssl_certificate_id: Option<i64>,
    pub is_enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamHost {
    pub id: i64,
    pub user_id: i64,
    pub incoming_port: u16,
    pub forward_host: String,
    pub forward_port: u16,
    pub tcp_forwarding: bool,
    pub udp_forwarding: bool,
    pub is_enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadHost {
    pub id: i64,
    pub user_id: i64,
    pub domain_names: Vec<String>,
    pub status_code: u16,
    pub custom_message: Option<String>,
    pub ssl_certificate_id: Option<i64>,
    pub is_enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessListItem {
    pub id: i64,
    pub access_list_id: i64,
    pub directive: String, // "allow" | "deny"
    pub address: String,   // IP or CIDR (e.g. 192.168.1.0/24)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessListAuth {
    pub id: i64,
    pub access_list_id: i64,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessList {
    pub id: i64,
    pub name: String,
    pub satisfy_any: bool,
    pub pass_auth_to_host: bool,
    pub items: Vec<AccessListItem>,
    pub auth_users: Vec<AccessListAuth>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub id: i64,
    pub provider: String, // "letsencrypt" | "custom"
    pub nice_name: String,
    pub domain_names: Vec<String>,
    pub expires_at: Option<String>,
    pub cert_path: String,
    pub key_path: String,
    pub intermediate_path: Option<String>,
    pub auto_renew: bool,
    pub is_valid: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub id: i64,
    pub user_id: i64,
    pub username: String,
    pub action: String,
    pub object_type: String,
    pub object_id: Option<String>,
    pub details: Option<String>,
    pub ip_address: Option<String>,
    pub created_at: String,
}
