package config

import (
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Server.AdminPort != 8443 {
		t.Errorf("expected admin port 8443, got %d", cfg.Server.AdminPort)
	}
	if cfg.Server.UserPort != 3000 {
		t.Errorf("expected user port 3000, got %d", cfg.Server.UserPort)
	}
	if cfg.Docker.NetworkDriver != "pasta" {
		t.Errorf("expected pasta driver, got %s", cfg.Docker.NetworkDriver)
	}
}
