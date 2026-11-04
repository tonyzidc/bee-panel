package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"html/template"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// GetDomainLogs reads the latest lines from access or error log for a domain
func (nm *NginxManager) GetDomainLogs(domain, logType string, lines int) ([]string, error) {
	if lines <= 0 {
		lines = 100
	}
	if lines > 1000 {
		lines = 1000
	}

	logFile := fmt.Sprintf("/var/log/nginx/%s.access.log", domain)
	if strings.ToLower(logType) == "error" {
		logFile = fmt.Sprintf("/var/log/nginx/%s.error.log", domain)
	}

	f, err := os.Open(logFile)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{"(No log entries generated yet for this domain)"}, nil
		}
		return nil, fmt.Errorf("open log file: %w", err)
	}
	defer f.Close()

	var allLines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		allLines = append(allLines, scanner.Text())
	}

	if len(allLines) <= lines {
		return allLines, nil
	}
	return allLines[len(allLines)-lines:], nil
}

// SaveCustomSSL writes custom SSL cert and key files to /etc/ssl/bee-panel/<domain>/
func (nm *NginxManager) SaveCustomSSL(domain, certContent, keyContent string) (string, string, error) {
	certDir := filepath.Join("/etc/ssl/bee-panel", domain)
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return "", "", fmt.Errorf("create ssl dir: %w", err)
	}

	certPath := filepath.Join(certDir, "fullchain.pem")
	keyPath := filepath.Join(certDir, "privkey.pem")

	if err := os.WriteFile(certPath, []byte(strings.TrimSpace(certContent)), 0644); err != nil {
		return "", "", fmt.Errorf("write ssl cert: %w", err)
	}

	if err := os.WriteFile(keyPath, []byte(strings.TrimSpace(keyContent)), 0600); err != nil {
		return "", "", fmt.Errorf("write ssl key: %w", err)
	}

	return certPath, keyPath, nil
}
