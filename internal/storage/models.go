package storage

import "time"

type AdminUser struct {
	ID           int64     `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	Email        string    `json:"email"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type Tenant struct {
	ID            int64     `json:"id"`
	Username      string    `json:"username"`
	UID           int       `json:"uid"`
	GID           int       `json:"gid"`
	HomeDir       string    `json:"home_dir"`
	Status        string    `json:"status"` // active, suspended, deleted
	DockerSocket  string    `json:"docker_socket"`
	PasswordPlain string    `json:"password,omitempty"`
	PrivateKey    string    `json:"private_key,omitempty"`
	PublicKey     string    `json:"public_key,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type DomainMapping struct {
	ID                  int64     `json:"id"`
	TenantID            int64     `json:"tenant_id"`
	TenantUsername      string    `json:"tenant_username,omitempty"`
	Domain              string    `json:"domain"`
	ExternalPort        int       `json:"external_port"`
	TargetContainerPort int       `json:"target_container_port"`
	EnableSSL           bool      `json:"enable_ssl"`
	SSLCertPath         string    `json:"ssl_cert_path"`
	SSLKeyPath          string    `json:"ssl_key_path"`
	SSLExpiryDate       string    `json:"ssl_expiry_date,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
}

type PortAllocation struct {
	ID        int64     `json:"id"`
	Port      int       `json:"port"`
	TenantID  int64     `json:"tenant_id"`
	Purpose   string    `json:"purpose"`
	CreatedAt time.Time `json:"created_at"`
}
