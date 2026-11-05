use crate::config::AppConfig;
use crate::db::models::{AccessList, DeadHost, ProxyHost, RedirectionHost, StreamHost};
use minijinja::{context, Environment};
use std::fs;
use std::path::Path;
use std::process::Command;

pub struct NginxEngine {
    env: Environment<'static>,
    config: AppConfig,
}

impl NginxEngine {
    pub fn new(config: AppConfig) -> anyhow::Result<Self> {
        let mut env = Environment::new();

        // Built-in templates
        let proxy_template = include_str!("../../templates/nginx/proxy_host.j2");
        let redir_template = include_str!("../../templates/nginx/redirection_host.j2");
        let stream_template = include_str!("../../templates/nginx/stream.j2");
        let dead_template = include_str!("../../templates/nginx/dead_host.j2");
        let access_template = include_str!("../../templates/nginx/access_list.j2");
        let default_template = include_str!("../../templates/nginx/default_host.j2");

        env.add_template_owned("proxy_host", proxy_template)?;
        env.add_template_owned("redirection_host", redir_template)?;
        env.add_template_owned("stream", stream_template)?;
        env.add_template_owned("dead_host", dead_template)?;
        env.add_template_owned("access_list", access_template)?;
        env.add_template_owned("default_host", default_template)?;

        Ok(Self { env, config })
    }

    pub fn render_proxy_host(
        &self,
        host: &ProxyHost,
        ssl_cert: Option<(&str, &str)>, // (cert_path, key_path)
    ) -> anyhow::Result<String> {
        let tmpl = self.env.get_template("proxy_host")?;
        let (ssl_cert_path, ssl_key_path) = match ssl_cert {
            Some((c, k)) => (c, k),
            None => ("", ""),
        };

        let rendered = tmpl.render(context! {
            domain_names => host.domain_names,
            forward_scheme => host.forward_scheme,
            forward_host => host.forward_host,
            forward_port => host.forward_port,
            caching_enabled => host.caching_enabled,
            block_exploits => host.block_exploits,
            websocket_support => host.websocket_support,
            ssl_certificate_id => host.ssl_certificate_id,
            ssl_cert_path => ssl_cert_path,
            ssl_key_path => ssl_key_path,
            ssl_forced => host.ssl_forced,
            http2_support => host.http2_support,
            hsts_enabled => host.hsts_enabled,
            hsts_subdomains => host.hsts_subdomains,
            access_list_id => host.access_list_id,
            custom_locations => host.custom_locations,
            advanced_config => host.advanced_config.as_deref().unwrap_or(""),
        })?;

        Ok(rendered)
    }

    pub fn render_redirection_host(
        &self,
        host: &RedirectionHost,
        ssl_cert: Option<(&str, &str)>,
    ) -> anyhow::Result<String> {
        let tmpl = self.env.get_template("redirection_host")?;
        let (ssl_cert_path, ssl_key_path) = match ssl_cert {
            Some((c, k)) => (c, k),
            None => ("", ""),
        };

        let rendered = tmpl.render(context! {
            domain_names => host.domain_names,
            forward_http_code => host.forward_http_code,
            forward_scheme => host.forward_scheme,
            forward_domain => host.forward_domain,
            preserve_path => host.preserve_path,
            block_exploits => host.block_exploits,
            ssl_certificate_id => host.ssl_certificate_id,
            ssl_cert_path => ssl_cert_path,
            ssl_key_path => ssl_key_path,
            http2_support => true,
        })?;

        Ok(rendered)
    }

    pub fn render_stream(&self, host: &StreamHost) -> anyhow::Result<String> {
        let tmpl = self.env.get_template("stream")?;
        let rendered = tmpl.render(context! {
            incoming_port => host.incoming_port,
            forward_host => host.forward_host,
            forward_port => host.forward_port,
            tcp_forwarding => host.tcp_forwarding,
            udp_forwarding => host.udp_forwarding,
        })?;

        Ok(rendered)
    }

    pub fn render_dead_host(
        &self,
        host: &DeadHost,
        ssl_cert: Option<(&str, &str)>,
    ) -> anyhow::Result<String> {
        let tmpl = self.env.get_template("dead_host")?;
        let (ssl_cert_path, ssl_key_path) = match ssl_cert {
            Some((c, k)) => (c, k),
            None => ("", ""),
        };

        let rendered = tmpl.render(context! {
            domain_names => host.domain_names,
            status_code => host.status_code,
            custom_message => host.custom_message.as_deref().unwrap_or("Host Disabled"),
            ssl_certificate_id => host.ssl_certificate_id,
            ssl_cert_path => ssl_cert_path,
            ssl_key_path => ssl_key_path,
            http2_support => true,
        })?;

        Ok(rendered)
    }

    pub fn render_access_list(&self, list: &AccessList) -> anyhow::Result<String> {
        let tmpl = self.env.get_template("access_list")?;
        let allow_ips: Vec<String> = list
            .items
            .iter()
            .filter(|i| i.directive == "allow")
            .map(|i| i.address.clone())
            .collect();

        let deny_ips: Vec<String> = list
            .items
            .iter()
            .filter(|i| i.directive == "deny")
            .map(|i| i.address.clone())
            .collect();

        let has_basic_auth = !list.auth_users.is_empty();

        let rendered = tmpl.render(context! {
            name => list.name,
            id => list.id,
            satisfy_any => list.satisfy_any,
            allow_ips => allow_ips,
            deny_ips => deny_ips,
            has_basic_auth => has_basic_auth,
        })?;

        Ok(rendered)
    }

    pub fn deploy_proxy_host(
        &self,
        host: &ProxyHost,
        ssl_cert: Option<(&str, &str)>,
    ) -> anyhow::Result<()> {
        let content = self.render_proxy_host(host, ssl_cert)?;
        let file_path = self.config.nginx_config_dir.join(format!("proxy_{}.conf", host.id));
        self.atomic_write_and_reload(&file_path, &content)
    }

    pub fn delete_proxy_host(&self, host_id: i64) -> anyhow::Result<()> {
        let file_path = self.config.nginx_config_dir.join(format!("proxy_{}.conf", host_id));
        if file_path.exists() {
            let _ = fs::remove_file(&file_path);
            self.test_and_reload()?;
        }
        Ok(())
    }

    pub fn deploy_redirection(
        &self,
        host: &RedirectionHost,
        ssl_cert: Option<(&str, &str)>,
    ) -> anyhow::Result<()> {
        let content = self.render_redirection_host(host, ssl_cert)?;
        let file_path = self.config.nginx_config_dir.join(format!("redir_{}.conf", host.id));
        self.atomic_write_and_reload(&file_path, &content)
    }

    pub fn delete_redirection(&self, host_id: i64) -> anyhow::Result<()> {
        let file_path = self.config.nginx_config_dir.join(format!("redir_{}.conf", host_id));
        if file_path.exists() {
            let _ = fs::remove_file(&file_path);
            self.test_and_reload()?;
        }
        Ok(())
    }

    pub fn deploy_stream(&self, host: &StreamHost) -> anyhow::Result<()> {
        let content = self.render_stream(host)?;
        let file_path = self.config.nginx_stream_dir.join(format!("stream_{}.conf", host.id));
        self.atomic_write_and_reload(&file_path, &content)
    }

    pub fn delete_stream(&self, host_id: i64) -> anyhow::Result<()> {
        let file_path = self.config.nginx_stream_dir.join(format!("stream_{}.conf", host_id));
        if file_path.exists() {
            let _ = fs::remove_file(&file_path);
            self.test_and_reload()?;
        }
        Ok(())
    }

    pub fn deploy_dead_host(
        &self,
        host: &DeadHost,
        ssl_cert: Option<(&str, &str)>,
    ) -> anyhow::Result<()> {
        let content = self.render_dead_host(host, ssl_cert)?;
        let file_path = self.config.nginx_config_dir.join(format!("dead_{}.conf", host.id));
        self.atomic_write_and_reload(&file_path, &content)
    }

    pub fn delete_dead_host(&self, host_id: i64) -> anyhow::Result<()> {
        let file_path = self.config.nginx_config_dir.join(format!("dead_{}.conf", host_id));
        if file_path.exists() {
            let _ = fs::remove_file(&file_path);
            self.test_and_reload()?;
        }
        Ok(())
    }

    pub fn deploy_access_list(&self, list: &AccessList) -> anyhow::Result<()> {
        let content = self.render_access_list(list)?;
        let file_path = self.config.nginx_access_dir.join(format!("{}.conf", list.id));
        fs::write(&file_path, content)?;

        // Write htpasswd if users exist
        if !list.auth_users.is_empty() {
            let htpasswd_path = self.config.nginx_access_dir.join(format!("htpasswd_{}", list.id));
            let mut htpasswd_lines = Vec::new();
            for u in &list.auth_users {
                htpasswd_lines.push(format!("{}:{}", u.username, u.password_hash));
            }
            fs::write(htpasswd_path, htpasswd_lines.join("\n"))?;
        }

        self.test_and_reload()
    }

    pub fn delete_access_list(&self, list_id: i64) -> anyhow::Result<()> {
        let file_path = self.config.nginx_access_dir.join(format!("{}.conf", list_id));
        let htpasswd_path = self.config.nginx_access_dir.join(format!("htpasswd_{}", list_id));
        let _ = fs::remove_file(file_path);
        let _ = fs::remove_file(htpasswd_path);
        self.test_and_reload()
    }

    fn atomic_write_and_reload(&self, path: &Path, content: &str) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let temp_path = path.with_extension("conf.tmp");
        fs::write(&temp_path, content)?;

        // Test syntax with temp file or rename and test
        // Standard Nginx test requires file in place
        let backup_content = if path.exists() {
            Some(fs::read_to_string(path)?)
        } else {
            None
        };

        fs::rename(&temp_path, path)?;

        if let Err(e) = self.test_and_reload() {
            // Rollback on syntax error
            if let Some(old) = backup_content {
                let _ = fs::write(path, old);
            } else {
                let _ = fs::remove_file(path);
            }
            return Err(e);
        }

        Ok(())
    }

    pub fn test_and_reload(&self) -> anyhow::Result<()> {
        // Check if nginx is installed
        let nginx_available = Command::new("which")
            .arg("nginx")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if !nginx_available {
            tracing::info!("Nginx not found in PATH. Skipping syntax test & reload (Dev mode).");
            return Ok(());
        }

        // Test syntax
        let test_output = Command::new("nginx")
            .arg("-t")
            .output()?;

        if !test_output.status.success() {
            let stderr = String::from_utf8_lossy(&test_output.stderr);
            return Err(anyhow::anyhow!("Nginx syntax test failed: {}", stderr));
        }

        // Reload Nginx
        let reload_cmd = if Command::new("which").arg("systemctl").output().map(|o| o.status.success()).unwrap_or(false) {
            Command::new("systemctl").args(&["reload", "nginx"]).output()
        } else {
            Command::new("nginx").args(&["-s", "reload"]).output()
        };

        match reload_cmd {
            Ok(output) if output.status.success() => {
                tracing::info!("Nginx successfully reloaded.");
                Ok(())
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                tracing::warn!("Nginx reload exited with status code: {}", stderr);
                Ok(())
            }
            Err(e) => {
                tracing::warn!("Failed to invoke reload command: {}", e);
                Ok(())
            }
        }
    }
}
