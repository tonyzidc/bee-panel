mod api;
mod config;
mod core;
mod db;
mod web;

use clap::{Parser, Subcommand};
use config::AppConfig;
use core::metrics::MetricsCollector;
use core::nginx::NginxEngine;
use db::create_pool;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser)]
#[command(name = "bee-panel")]
#[command(author = "Bee Panel Team")]
#[command(version = "2.0.0")]
#[command(about = "Ultra-lightweight Native Rust Reverse Proxy & Linux OS Host Manager", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the Bee Panel web daemon (Default)
    Serve,
    /// Display system and panel status
    Status,
    /// Reset administrator or user password
    ResetPassword {
        #[arg(default_value = "admin")]
        username: String,
    },
    /// List all provisioned users and SSH statuses
    UserList,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "bee_panel=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();
    let config = AppConfig::load();
    config.ensure_directories()?;

    match cli.command.unwrap_or(Commands::Serve) {
        Commands::Serve => run_server(config).await?,
        Commands::Status => run_status(config)?,
        Commands::ResetPassword { username } => run_reset_password(config, &username)?,
        Commands::UserList => run_user_list(config)?,
    }

    Ok(())
}

async fn run_server(config: AppConfig) -> anyhow::Result<()> {
    tracing::info!("🐝 Starting Bee Panel v2.0.0 (Native Rust Engine)...");

    // Initialize Database
    let pool = create_pool(&config.database_path)?;
    tracing::info!("Database initialized at {:?}", config.database_path);

    // Initialize Native Nginx environment
    if let Ok(nginx) = NginxEngine::new(config.clone()) {
        if let Err(error) = nginx.ensure_default_host() {
            tracing::warn!("Could not install default ACME host: {}", error);
        }
        if let Err(error) = nginx.test_and_reload() {
            tracing::warn!("Nginx validation failed: {}", error);
        }
    }

    // Shared State & Metrics Collector
    let metrics_collector = Arc::new(Mutex::new(MetricsCollector::new()));
    let shared_config = Arc::new(config.clone());

    // Background task: Auto-renew SSL certificates every 12 hours
    let renewal_pool = pool.clone();
    let renewal_config = shared_config.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(43200));
        loop {
            interval.tick().await;
            tracing::info!("Running scheduled ACME SSL renewal check...");
            if let Err(error) =
                api::certificates::renew_due_certificates(&renewal_pool, &renewal_config).await
            {
                tracing::error!("SSL renewal check failed: {}", error);
            }
        }
    });

    // Setup CORS
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // API Routes + Embedded Static Assets (SPA)
    let api_router = api::create_api_router(pool)
        .layer(axum::Extension(shared_config))
        .layer(axum::Extension(metrics_collector));

    let app = axum::Router::new()
        .merge(api_router)
        .fallback(web::static_handler)
        .layer(TraceLayer::new_for_http())
        .layer(cors);

    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    tracing::info!("🌐 Bee Panel v2 Web UI listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

fn run_status(_config: AppConfig) -> anyhow::Result<()> {
    let mut collector = MetricsCollector::new();
    let m = collector.collect();

    println!("==================================================");
    println!("🐝 Bee Panel v2 - System & Engine Status");
    println!("==================================================");
    println!("Hostname:       {}", m.hostname);
    println!("OS:             {}", m.os_name);
    println!("Kernel:         {}", m.kernel_version);
    println!("Uptime:         {} hours", m.uptime_seconds / 3600);
    println!(
        "CPU Usage:      {:.1}% ({} cores)",
        m.cpu_usage_percent, m.cpu_count
    );
    println!(
        "Memory:         {:.1}% ({:.0} MB / {:.0} MB)",
        m.memory_usage_percent,
        m.memory_used_bytes as f64 / 1024.0 / 1024.0,
        m.memory_total_bytes as f64 / 1024.0 / 1024.0
    );
    println!(
        "Disk:           {:.1}% ({:.1} GB / {:.1} GB)",
        m.disk_usage_percent,
        m.disk_used_bytes as f64 / 1024.0 / 1024.0 / 1024.0,
        m.disk_total_bytes as f64 / 1024.0 / 1024.0 / 1024.0
    );
    println!(
        "Nginx Status:   {}",
        if m.nginx_running {
            "RUNNING"
        } else {
            "STOPPED"
        }
    );
    if let Some(v) = m.nginx_version {
        println!("Nginx Version:  {}", v);
    }
    println!("==================================================");

    Ok(())
}

fn run_reset_password(config: AppConfig, username: &str) -> anyhow::Result<()> {
    use argon2::{
        password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
        Argon2,
    };
    use rusqlite::Connection;

    let conn = Connection::open(&config.database_path)?;
    let new_password = core::ssh_user::generate_secure_password(24);
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(new_password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("Argon2 error: {}", e))?
        .to_string();

    let updated = conn.execute(
        "UPDATE users SET password_hash = ?1, updated_at = datetime('now') WHERE username = ?2",
        rusqlite::params![&hash, username],
    )?;

    if updated > 0 {
        println!(
            "✅ Password for user '{}' successfully reset to '{}'",
            username, new_password
        );
    } else {
        println!("❌ User '{}' not found in database.", username);
    }

    Ok(())
}

fn run_user_list(config: AppConfig) -> anyhow::Result<()> {
    use rusqlite::Connection;

    let conn = Connection::open(&config.database_path)?;
    let mut stmt = conn.prepare(
        "SELECT u.id, u.username, u.role, u.shell_mode, s.public_key 
         FROM users u LEFT JOIN ssh_credentials s ON u.id = s.user_id",
    )?;

    println!(
        "{:<6} {:<16} {:<10} {:<16} {:<30}",
        "ID", "USERNAME", "ROLE", "SHELL_MODE", "SSH PUBLIC KEY"
    );
    println!("--------------------------------------------------------------------------------");

    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, Option<String>>(4)?
                .unwrap_or_else(|| "N/A".to_string()),
        ))
    })?;

    for row in rows {
        let (id, user, role, shell, key) = row?;
        let short_key = if key.len() > 30 {
            format!("{}...", &key[..27])
        } else {
            key
        };
        println!(
            "{:<6} {:<16} {:<10} {:<16} {:<30}",
            id, user, role, shell, short_key
        );
    }

    Ok(())
}
