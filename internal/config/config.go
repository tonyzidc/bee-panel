package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server struct {
		AdminPort      int    `yaml:"admin_port"`
		UserPort       int    `yaml:"user_port"`
		Host           string `yaml:"host"`
		JWTSecret      string `yaml:"jwt_secret"`
		JWTExpiryHours int    `yaml:"jwt_expiry_hours"`
	} `yaml:"server"`

	Storage struct {
		DBPath string `yaml:"db_path"`
	} `yaml:"storage"`

	Ports struct {
		MinPort int `yaml:"min_port"`
		MaxPort int `yaml:"max_port"`
	} `yaml:"ports"`

	Proxy struct {
		NginxConfDir    string `yaml:"nginx_conf_dir"`
		NginxEnabledDir string `yaml:"nginx_enabled_dir"`
		AcmeWebroot     string `yaml:"acme_webroot"`
	} `yaml:"proxy"`

	Docker struct {
		NetworkDriver string `yaml:"network_driver"`
	} `yaml:"docker"`
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
	return cfg
}

func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()

	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config yaml: %w", err)
	}

	return cfg, nil
}
