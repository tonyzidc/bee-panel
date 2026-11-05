use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub host: String,
    pub port: u16,
    pub jwt_secret: String,
    pub database_path: PathBuf,
    pub nginx_config_dir: PathBuf,
    pub nginx_stream_dir: PathBuf,
    pub nginx_access_dir: PathBuf,
    pub acme_challenge_dir: PathBuf,
    pub certs_dir: PathBuf,
    pub web_roots_dir: PathBuf,
}

impl Default for AppConfig {
    fn default() -> Self {
        let is_root = unsafe { libc::geteuid() == 0 };
        let base_dir = if is_root {
            PathBuf::from("/etc/bee-panel")
        } else {
            dirs_fallback_path()
        };

        let nginx_base = if is_root {
            PathBuf::from("/etc/nginx/bee-panel")
        } else {
            base_dir.join("nginx")
        };

        Self {
            host: std::env::var("BEE_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: std::env::var("BEE_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(8443),
            jwt_secret: std::env::var("BEE_JWT_SECRET")
                .unwrap_or_else(|_| "bee-panel-super-secret-jwt-key-change-in-production".to_string()),
            database_path: base_dir.join("bee-panel.db"),
            nginx_config_dir: nginx_base.join("conf.d"),
            nginx_stream_dir: nginx_base.join("streams.d"),
            nginx_access_dir: nginx_base.join("access"),
            acme_challenge_dir: PathBuf::from("/var/lib/bee-panel/acme-challenges"),
            certs_dir: base_dir.join("certs"),
            web_roots_dir: PathBuf::from("/var/www/vhosts"),
        }
    }
}

fn dirs_fallback_path() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".bee-panel")
    } else {
        PathBuf::from("./data")
    }
}

impl AppConfig {
    pub fn load() -> Self {
        let default_config = Self::default();
        let config_path = PathBuf::from("/etc/bee-panel/config.yaml");

        if config_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&config_path) {
                if let Ok(cfg) = serde_yaml::from_str(&content) {
                    return cfg;
                }
            }
        }

        default_config
    }

    pub fn ensure_directories(&self) -> std::io::Result<()> {
        if let Some(parent) = self.database_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::create_dir_all(&self.nginx_config_dir)?;
        std::fs::create_dir_all(&self.nginx_stream_dir)?;
        std::fs::create_dir_all(&self.nginx_access_dir)?;
        let _ = std::fs::create_dir_all(&self.acme_challenge_dir);
        let _ = std::fs::create_dir_all(&self.certs_dir);
        let _ = std::fs::create_dir_all(&self.web_roots_dir);
        Ok(())
    }
}
