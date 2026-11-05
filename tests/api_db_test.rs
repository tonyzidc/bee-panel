use rusqlite::Connection;

#[test]
fn test_database_schema_and_crud() {
    let conn = Connection::open_in_memory().unwrap();

    // Execute schema
    conn.execute_batch(
        r#"
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'tenant',
            shell_mode TEXT NOT NULL DEFAULT 'sftp_only',
            is_disabled INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE ssh_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            public_key TEXT NOT NULL,
            private_key_pem TEXT NOT NULL,
            initial_password TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE proxy_hosts (
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
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        "#,
    )
    .unwrap();

    // Insert user
    conn.execute(
        "INSERT INTO users (username, password_hash, role, shell_mode) VALUES ('tony', 'hash123', 'admin', 'sudo_admin')",
        [],
    )
    .unwrap();
    let user_id = conn.last_insert_rowid();
    assert_eq!(user_id, 1);

    // Insert SSH credential
    conn.execute(
        "INSERT INTO ssh_credentials (user_id, public_key, private_key_pem, initial_password) 
         VALUES (?1, 'ssh-ed25519 AAAAC3...', '-----BEGIN OPENSSH PRIVATE KEY-----...', 'secret_pass')",
        rusqlite::params![user_id],
    )
    .unwrap();

    // Query SSH credential
    let (u_id, pass): (i64, String) = conn
        .query_row(
            "SELECT user_id, initial_password FROM ssh_credentials WHERE user_id = ?1",
            [user_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(u_id, 1);
    assert_eq!(pass, "secret_pass");

    // Insert Proxy Host
    conn.execute(
        "INSERT INTO proxy_hosts (user_id, domain_names, forward_scheme, forward_host, forward_port) 
         VALUES (?1, '[\"demo.example.com\"]', 'http', '127.0.0.1', 8080)",
        rusqlite::params![user_id],
    )
    .unwrap();

    let count: i64 = conn.query_row("SELECT count(*) FROM proxy_hosts", [], |r| r.get(0)).unwrap();
    assert_eq!(count, 1);
}
