package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"path/filepath"
	"time"
)

type CertificateInfo struct {
	CertPath string `json:"cert_path"`
	KeyPath  string `json:"key_path"`
}

type SSLManager struct {
	acmeWebroot string
	adminEmail  string
	logger      *slog.Logger
}

func NewSSLManager(acmeWebroot, adminEmail string, logger *slog.Logger) *SSLManager {
	if acmeWebroot == "" {
		acmeWebroot = "/var/www/bee-acme"
	}
	if adminEmail == "" {
		adminEmail = "admin@bee-panel.local"
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &SSLManager{
		acmeWebroot: acmeWebroot,
		adminEmail:  adminEmail,
		logger:      logger,
	}
}

// PreCheckDNS checks if domain has valid A/AAAA records pointing to public internet
func (sm *SSLManager) PreCheckDNS(domain string) (bool, error) {
	ips, err := net.LookupIP(domain)
	if err != nil || len(ips) == 0 {
		return false, fmt.Errorf("domain '%s' has no DNS A/AAAA records: %w", domain, err)
	}
	return true, nil
}

// RequestCertificate executes certbot in non-interactive webroot mode
func (sm *SSLManager) RequestCertificate(domain string) (certPath, keyPath string, err error) {
	sm.logger.Info("Validating DNS for domain before ACME challenge", "domain", domain)
	if _, err := sm.PreCheckDNS(domain); err != nil {
		return "", "", fmt.Errorf("DNS validation failed: %w", err)
	}

	sm.logger.Info("Requesting Let's Encrypt certificate via Certbot webroot mode",
		"domain", domain,
		"webroot", sm.acmeWebroot,
	)

	args := []string{
		"certonly",
		"--webroot",
		"-w", sm.acmeWebroot,
		"-d", domain,
		"--email", sm.adminEmail,
		"--agree-tos",
		"--no-eff-email",
		"--non-interactive",
		"--keep-until-expiring",
	}

	cmd := exec.Command("certbot", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("certbot failed: %s (%w)", string(out), err)
	}

	certPath = filepath.Join("/etc/letsencrypt/live", domain, "fullchain.pem")
	keyPath = filepath.Join("/etc/letsencrypt/live", domain, "privkey.pem")

	sm.logger.Info("SSL Certificate issued successfully", "domain", domain, "certPath", certPath)
	return certPath, keyPath, nil
}

// ObtainCertificate wraps RequestCertificate and returns *CertificateInfo
func (sm *SSLManager) ObtainCertificate(domain string) (*CertificateInfo, error) {
	cPath, kPath, err := sm.RequestCertificate(domain)
	if err != nil {
		return nil, err
	}
	return &CertificateInfo{CertPath: cPath, KeyPath: kPath}, nil
}

// StartAutoRenewWorker starts a background periodic worker to renew certificates
func (sm *SSLManager) StartAutoRenewWorker(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 12 * time.Hour
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				sm.logger.Info("SSL auto-renew worker stopped")
				return
			case <-ticker.C:
				sm.logger.Info("Executing periodic SSL certificate renewal check...")
				cmd := exec.Command("certbot", "renew", "--quiet", "--post-hook", "nginx -s reload")
				if out, err := cmd.CombinedOutput(); err != nil {
					sm.logger.Error("SSL renew check failed", "error", err, "output", string(out))
				} else {
					sm.logger.Info("SSL renew check completed successfully")
				}
			}
		}
	}()
}
