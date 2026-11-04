package proxy

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"os/exec"
	"path/filepath"
)

type VHostConfig struct {
	Domain              string
	ExternalPort        int
	TargetContainerPort int
	EnableSSL           bool
	SSLCertPath         string
	SSLKeyPath          string
	AcmeWebroot         string
}

type NginxManager struct {
	availableDir string
	enabledDir   string
	templateText string
	acmeWebroot  string
}

func NewNginxManager(availableDir, enabledDir, acmeWebroot, templateText string) *NginxManager {
	if availableDir == "" {
		availableDir = "/etc/nginx/sites-available"
	}
	if enabledDir == "" {
		enabledDir = "/etc/nginx/sites-enabled"
	}
	if acmeWebroot == "" {
		acmeWebroot = "/var/www/bee-acme"
	}
	return &NginxManager{
		availableDir: availableDir,
		enabledDir:   enabledDir,
		templateText: templateText,
		acmeWebroot:  acmeWebroot,
	}
}

// RenderVHost renders the nginx vhost config string from template
func (nm *NginxManager) RenderVHost(cfg *VHostConfig) (string, error) {
	if cfg.AcmeWebroot == "" {
		cfg.AcmeWebroot = nm.acmeWebroot
	}
	if cfg.ExternalPort <= 0 {
		if cfg.EnableSSL {
			cfg.ExternalPort = 443
		} else {
			cfg.ExternalPort = 80
		}
	}

	tmpl, err := template.New("nginx_vhost").Parse(nm.templateText)
	if err != nil {
		return "", fmt.Errorf("parse nginx template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, cfg); err != nil {
		return "", fmt.Errorf("execute nginx template: %w", err)
	}

	return buf.String(), nil
}

// ApplyVHost writes the configuration, symlinks it, validates syntax via nginx -t, and reloads
func (nm *NginxManager) ApplyVHost(cfg *VHostConfig) error {
	rendered, err := nm.RenderVHost(cfg)
	if err != nil {
		return err
	}

	_ = os.MkdirAll(nm.availableDir, 0755)
	_ = os.MkdirAll(nm.enabledDir, 0755)

	confFile := fmt.Sprintf("%s.conf", cfg.Domain)
	availPath := filepath.Join(nm.availableDir, confFile)
	enablePath := filepath.Join(nm.enabledDir, confFile)

	// Backup existing if any
	oldContent, _ := os.ReadFile(availPath)

	// 1. Write to sites-available
	if err := os.WriteFile(availPath, []byte(rendered), 0644); err != nil {
		return fmt.Errorf("write %s: %w", availPath, err)
	}

	// 2. Create symlink to sites-enabled
	_ = os.Remove(enablePath)
	if err := os.Symlink(availPath, enablePath); err != nil {
		return fmt.Errorf("symlink %s -> %s: %w", enablePath, availPath, err)
	}

	// 3. Test Nginx configuration syntax (nginx -t)
	testCmd := exec.Command("nginx", "-t")
	if out, err := testCmd.CombinedOutput(); err != nil {
		// Rollback on syntax error
		_ = os.Remove(enablePath)
		if len(oldContent) > 0 {
			_ = os.WriteFile(availPath, oldContent, 0644)
			_ = os.Symlink(availPath, enablePath)
		} else {
			_ = os.Remove(availPath)
		}
		return fmt.Errorf("nginx -t failed: %s (%w)", string(out), err)
	}

	// 4. Reload Nginx
	reloadCmd := exec.Command("nginx", "-s", "reload")
	if out, err := reloadCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nginx -s reload failed: %s (%w)", string(out), err)
	}

	return nil
}

// RemoveVHost removes the vhost configuration and reloads Nginx
func (nm *NginxManager) RemoveVHost(domain string) error {
	confFile := fmt.Sprintf("%s.conf", domain)
	availPath := filepath.Join(nm.availableDir, confFile)
	enablePath := filepath.Join(nm.enabledDir, confFile)

	_ = os.Remove(enablePath)
	_ = os.Remove(availPath)

	// Test syntax and reload
	_ = exec.Command("nginx", "-t").Run()
	_ = exec.Command("nginx", "-s", "reload").Run()
	return nil
}
