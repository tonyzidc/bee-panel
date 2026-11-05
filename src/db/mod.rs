pub mod models;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;
use std::path::Path;

pub type DbPool = Pool<SqliteConnectionManager>;

pub fn create_pool(database_path: &Path) -> anyhow::Result<DbPool> {
    if let Some(parent) = database_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let setup = Connection::open(database_path)?;
    setup.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;
    drop(setup);

    let manager = SqliteConnectionManager::file(database_path).with_init(|c| {
        c.execute_batch(
            "PRAGMA foreign_keys = ON;
                 PRAGMA busy_timeout = 5000;",
        )
    });

    let pool = Pool::builder().max_size(16).build(manager)?;

    // Run schema migrations
    let conn = pool.get()?;
    init_schema(&conn)?;

    Ok(pool)
}

fn init_schema(conn: &Connection) -> anyhow::Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'tenant',
            shell_mode TEXT NOT NULL DEFAULT 'sftp_only',
            is_disabled INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS ssh_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            public_key TEXT NOT NULL,
            private_key_pem TEXT NOT NULL,
            initial_password TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT NOT NULL,
            nice_name TEXT NOT NULL,
            domain_names TEXT NOT NULL,
            expires_at TEXT,
            cert_path TEXT NOT NULL,
            key_path TEXT NOT NULL,
            intermediate_path TEXT,
            auto_renew INTEGER NOT NULL DEFAULT 1,
            contact_email TEXT,
            is_staging INTEGER NOT NULL DEFAULT 0,
            is_valid INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS access_lists (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            satisfy_any INTEGER NOT NULL DEFAULT 0,
            pass_auth_to_host INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS access_list_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            access_list_id INTEGER NOT NULL,
            directive TEXT NOT NULL,
            address TEXT NOT NULL,
            FOREIGN KEY (access_list_id) REFERENCES access_lists(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS access_list_auths (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            access_list_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            FOREIGN KEY (access_list_id) REFERENCES access_lists(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS proxy_hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            domain_names TEXT NOT NULL,
            forward_scheme TEXT NOT NULL DEFAULT 'http',
            forward_host TEXT NOT NULL,
            forward_port INTEGER NOT NULL,
            caching_enabled INTEGER NOT NULL DEFAULT 0,
            block_exploits INTEGER NOT NULL DEFAULT 1,
            websocket_support INTEGER NOT NULL DEFAULT 1,
            ssl_certificate_id INTEGER,
            ssl_forced INTEGER NOT NULL DEFAULT 0,
            http2_support INTEGER NOT NULL DEFAULT 1,
            hsts_enabled INTEGER NOT NULL DEFAULT 0,
            hsts_subdomains INTEGER NOT NULL DEFAULT 0,
            access_list_id INTEGER,
            advanced_config TEXT,
            is_enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (ssl_certificate_id) REFERENCES certificates(id) ON DELETE SET NULL,
            FOREIGN KEY (access_list_id) REFERENCES access_lists(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS custom_locations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            proxy_host_id INTEGER NOT NULL,
            path TEXT NOT NULL,
            forward_scheme TEXT NOT NULL DEFAULT 'http',
            forward_host TEXT NOT NULL,
            forward_port INTEGER NOT NULL,
            advanced_config TEXT,
            FOREIGN KEY (proxy_host_id) REFERENCES proxy_hosts(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS redirection_hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            domain_names TEXT NOT NULL,
            forward_http_code INTEGER NOT NULL DEFAULT 301,
            forward_scheme TEXT NOT NULL DEFAULT 'https',
            forward_domain TEXT NOT NULL,
            preserve_path INTEGER NOT NULL DEFAULT 1,
            block_exploits INTEGER NOT NULL DEFAULT 1,
            ssl_certificate_id INTEGER,
            is_enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (ssl_certificate_id) REFERENCES certificates(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS stream_hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            incoming_port INTEGER NOT NULL UNIQUE,
            forward_host TEXT NOT NULL,
            forward_port INTEGER NOT NULL,
            tcp_forwarding INTEGER NOT NULL DEFAULT 1,
            udp_forwarding INTEGER NOT NULL DEFAULT 0,
            is_enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS dead_hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            domain_names TEXT NOT NULL,
            status_code INTEGER NOT NULL DEFAULT 404,
            custom_message TEXT,
            ssl_certificate_id INTEGER,
            is_enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (ssl_certificate_id) REFERENCES certificates(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            object_type TEXT NOT NULL,
            object_id TEXT,
            details TEXT,
            ip_address TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        "#,
    )?;

    // Existing installations predate the renewal metadata.
    let mut columns = conn.prepare("PRAGMA table_info(certificates)")?;
    let names = columns
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(columns);
    if !names.iter().any(|name| name == "contact_email") {
        conn.execute("ALTER TABLE certificates ADD COLUMN contact_email TEXT", [])?;
    }
    if !names.iter().any(|name| name == "is_staging") {
        conn.execute(
            "ALTER TABLE certificates ADD COLUMN is_staging INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }

    // Seed default admin if no users exist
    let count: i64 = conn.query_row("SELECT count(*) FROM users", [], |r| r.get(0))?;
    if count == 0 {
        use argon2::{
            password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
            Argon2,
        };
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let initial_password = crate::core::ssh_user::generate_secure_password(24);
        let password_hash = argon2
            .hash_password(initial_password.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("Failed to hash password: {}", e))?
            .to_string();

        conn.execute(
            "INSERT INTO users (username, password_hash, role, shell_mode, is_disabled) 
             VALUES ('admin', ?1, 'admin', 'sudo_admin', 0)",
            [&password_hash],
        )?;

        if let Some(parent) = conn.path().and_then(|p| Path::new(p).parent()) {
            let password_file = parent.join("initial-admin-password");
            std::fs::write(&password_file, &initial_password)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&password_file, std::fs::Permissions::from_mode(0o600))?;
            }
            tracing::info!("Initial admin password saved to {:?}", password_file);
        }
    }

    Ok(())
}
