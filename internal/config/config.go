package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	LoadedFrom string `yaml:"-" json:"loaded_from"`

	Server struct {
		AdminPort      int    `yaml:"admin_port" json:"admin_port"`
		UserPort       int    `yaml:"user_port" json:"user_port"`
		Host           string `yaml:"host" json:"host"`
		JWTSecret      string `yaml:"jwt_secret" json:"jwt_secret"`
		JWTExpiryHours int    `yaml:"jwt_expiry_hours" json:"jwt_expiry_hours"`
		PanelDomain    string `yaml:"panel_domain" json:"panel_domain"`
		PanelSSL       bool   `yaml:"panel_ssl" json:"panel_ssl"`
	} `yaml:"server" json:"server"`

	Storage struct {
		DBPath string `yaml:"db_path" json:"db_path"`
	} `yaml:"storage" json:"storage"`

	Ports struct {
		MinPort int `yaml:"min_port" json:"min_port"`
		MaxPort int `yaml:"max_port" json:"max_port"`
	} `yaml:"ports" json:"ports"`

	Proxy struct {
		NginxConfDir    string `yaml:"nginx_conf_dir" json:"nginx_conf_dir"`
		NginxEnabledDir string `yaml:"nginx_enabled_dir" json:"nginx_enabled_dir"`
		AcmeWebroot     string `yaml:"acme_webroot" json:"acme_webroot"`
	} `yaml:"proxy" json:"proxy"`

	Docker struct {
		NetworkDriver string `yaml:"network_driver" json:"network_driver"`
	} `yaml:"docker" json:"docker"`

	Telegram struct {
		Enabled               bool   `yaml:"enabled" json:"enabled"`
		BotToken              string `yaml:"bot_token" json:"bot_token"`
		ChatID                string `yaml:"chat_id" json:"chat_id"`
		NotifyOnLogin         bool   `yaml:"notify_on_login" json:"notify_on_login"`
		NotifyOnTenantCreated bool   `yaml:"notify_on_tenant_created" json:"notify_on_tenant_created"`
		NotifyOnSSL           bool   `yaml:"notify_on_ssl" json:"notify_on_ssl"`
		NotifyOnSecurity      bool   `yaml:"notify_on_security" json:"notify_on_security"`
	} `yaml:"telegram" json:"telegram"`
}

func DefaultConfig() *Config {
	cfg := &Config{}
	cfg.Server.AdminPort = 8443
	cfg.Server.UserPort = 3000
	cfg.Server.Host = "0.0.0.0"
	cfg.Server.JWTSecret = "bee-panel-default-secret-key-32-chars-long"
	cfg.Server.JWTExpiryHours = 72

	cfg.Storage.DBPath = "/var/lib/bee-panel/bee-panel.db"
	cfg.Ports.MinPort = 10000
	cfg.Ports.MaxPort = 60000

	cfg.Proxy.NginxConfDir = "/etc/nginx/sites-available"
	cfg.Proxy.NginxEnabledDir = "/etc/nginx/sites-enabled"
	cfg.Proxy.AcmeWebroot = "/var/www/bee-acme"

	cfg.Docker.NetworkDriver = "pasta"

	cfg.Telegram.Enabled = false
	cfg.Telegram.NotifyOnLogin = true
	cfg.Telegram.NotifyOnTenantCreated = true
	cfg.Telegram.NotifyOnSSL = true
	cfg.Telegram.NotifyOnSecurity = true

	return cfg
}

func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()

	candidatePaths := []string{}
	if path != "" {
		candidatePaths = append(candidatePaths, path)
	} else {
		candidatePaths = append(candidatePaths,
			"/etc/bee-panel/bee-panel.yaml",
			"/var/lib/bee-panel/bee-panel.yaml",
			"./configs/bee-panel.yaml",
		)
	}

	var foundPath string
	var data []byte
	var err error

	for _, p := range candidatePaths {
		if data, err = os.ReadFile(p); err == nil {
			foundPath = p
			break
		}
	}

	if foundPath == "" {
		// If explicit path was given and didn't exist
		if path != "" {
			return nil, fmt.Errorf("read config file: %w", err)
		}
		// Fallback to default
		cfg.LoadedFrom = "/etc/bee-panel/bee-panel.yaml"
		return cfg, nil
	}

	cfg.LoadedFrom = foundPath
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config yaml: %w", err)
	}

	return cfg, nil
}

func SaveConfig(path string, cfg *Config) error {
	if path == "" {
		path = cfg.LoadedFrom
	}
	if path == "" {
		path = "/etc/bee-panel/bee-panel.yaml"
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	return os.WriteFile(path, data, 0644)
}
