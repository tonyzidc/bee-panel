package storage

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

type DB struct {
	conn *sql.DB
}

func OpenDB(dbPath string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, fmt.Errorf("create db directory: %w", err)
	}

	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(1)", dbPath)
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}

	conn.SetMaxOpenConns(1)
	conn.SetMaxIdleConns(1)
	conn.SetConnMaxLifetime(time.Hour)

	db := &DB{conn: conn}
	if err := db.migrate(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("migrate db schema: %w", err)
	}

	return db, nil
}

func (db *DB) Close() error {
	return db.conn.Close()
}

func (db *DB) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS admin_users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		email TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS tenants (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		uid INTEGER NOT NULL,
		gid INTEGER NOT NULL,
		home_dir TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'active',
		docker_socket TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS domain_mappings (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		tenant_id INTEGER NOT NULL,
		domain TEXT UNIQUE NOT NULL,
		external_port INTEGER NOT NULL DEFAULT 80,
		target_container_port INTEGER NOT NULL,
		enable_ssl BOOLEAN NOT NULL DEFAULT 0,
		ssl_cert_path TEXT,
		ssl_key_path TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS port_allocations (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		port INTEGER UNIQUE NOT NULL,
		tenant_id INTEGER NOT NULL,
		purpose TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
	);
	`
	_, err := db.conn.Exec(schema)
	return err
}

// IsSetupCompleted checks if at least one admin account exists
func (db *DB) IsSetupCompleted() (bool, error) {
	var count int
	err := db.conn.QueryRow("SELECT COUNT(*) FROM admin_users").Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// CreateAdmin registers the initial or additional admin user
func (db *DB) CreateAdmin(username, password, email string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	_, err = db.conn.Exec(
		"INSERT INTO admin_users (username, password_hash, email, created_at, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
		username, string(hash), email,
	)
	return err
}

// AuthenticateAdmin checks username and password against database
func (db *DB) AuthenticateAdmin(username, password string) (*AdminUser, error) {
	user := &AdminUser{}
	err := db.conn.QueryRow(
		"SELECT id, username, password_hash, email, created_at, updated_at FROM admin_users WHERE username = ?",
		username,
	).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Email, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	return user, nil
}

// CreateTenant inserts a new tenant record into sqlite
func (db *DB) CreateTenant(username string, uid, gid int, homeDir, dockerSocket string) (*Tenant, error) {
	res, err := db.conn.Exec(
		"INSERT INTO tenants (username, uid, gid, home_dir, status, docker_socket, created_at, updated_at) VALUES (?, ?, ?, ?, 'active', ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
		username, uid, gid, homeDir, dockerSocket,
	)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &Tenant{
		ID:           id,
		Username:     username,
		UID:          uid,
		GID:          gid,
		HomeDir:      homeDir,
		Status:       "active",
		DockerSocket: dockerSocket,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}, nil
}

// ListTenants returns all tenants
func (db *DB) ListTenants() ([]*Tenant, error) {
	rows, err := db.conn.Query("SELECT id, username, uid, gid, home_dir, status, docker_socket, created_at, updated_at FROM tenants ORDER BY id DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*Tenant
	for rows.Next() {
		t := &Tenant{}
		if err := rows.Scan(&t.ID, &t.Username, &t.UID, &t.GID, &t.HomeDir, &t.Status, &t.DockerSocket, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		list = append(list, t)
	}
	return list, nil
}

// DeleteTenant deletes a tenant record from sqlite
func (db *DB) DeleteTenant(username string) error {
	_, err := db.conn.Exec("DELETE FROM tenants WHERE username = ?", username)
	return err
}

// SaveDomainMapping saves or updates a domain mapping
func (db *DB) SaveDomainMapping(m *DomainMapping) error {
	res, err := db.conn.Exec(
		"INSERT INTO domain_mappings (tenant_id, domain, external_port, target_container_port, enable_ssl, ssl_cert_path, ssl_key_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
		m.TenantID, m.Domain, m.ExternalPort, m.TargetContainerPort, m.EnableSSL, m.SSLCertPath, m.SSLKeyPath,
	)
	if err != nil {
		return err
	}
	m.ID, _ = res.LastInsertId()
	return nil
}

// ListDomainMappings returns domain mappings for a tenant
func (db *DB) ListDomainMappings(tenantID int64) ([]*DomainMapping, error) {
	query := "SELECT id, tenant_id, domain, external_port, target_container_port, enable_ssl, ssl_cert_path, ssl_key_path, created_at FROM domain_mappings"
	var rows *sql.Rows
	var err error
	if tenantID > 0 {
		rows, err = db.conn.Query(query+" WHERE tenant_id = ? ORDER BY id DESC", tenantID)
	} else {
		rows, err = db.conn.Query(query + " ORDER BY id DESC")
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*DomainMapping
	for rows.Next() {
		m := &DomainMapping{}
		if err := rows.Scan(&m.ID, &m.TenantID, &m.Domain, &m.ExternalPort, &m.TargetContainerPort, &m.EnableSSL, &m.SSLCertPath, &m.SSLKeyPath, &m.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, m)
	}
	return list, nil
}

// DeleteDomainMapping deletes a domain mapping
func (db *DB) DeleteDomainMapping(domain string) error {
	_, err := db.conn.Exec("DELETE FROM domain_mappings WHERE domain = ?", domain)
	return err
}
