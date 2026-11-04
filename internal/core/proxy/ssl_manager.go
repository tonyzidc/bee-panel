package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	if adminEmail == "" || !strings.Contains(adminEmail, "@") {
		adminEmail = "devops@cloudbee.io"
	}
	return &SSLManager{
		acmeWebroot: acmeWebroot,
		adminEmail:  adminEmail,
		logger:      logger,
	}
}

// IsIP returns true if target string is a valid IPv4 or IPv6 address
func (sm *SSLManager) IsIP(target string) bool {
	return net.ParseIP(strings.TrimSpace(target)) != nil
}

// PreCheckDNS checks if domain has valid A/AAAA records pointing to public internet
func (sm *SSLManager) PreCheckDNS(domain string) (bool, error) {
	if sm.IsIP(domain) {
		return true, nil
	}
	ips, err := net.LookupIP(domain)
	if err != nil || len(ips) == 0 {
		return false, fmt.Errorf("domain '%s' has no DNS A/AAAA records: %w", domain, err)
	}
	return true, nil
}

// ensureAcmeSh locates or installs acme.sh
func (sm *SSLManager) ensureAcmeSh() (string, error) {
	if path, err := exec.LookPath("acme.sh"); err == nil {
		return path, nil
	}
	// Common install locations
	candidates := []string{
		"/usr/local/bin/acme.sh",
		"/root/.acme.sh/acme.sh",
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}

	sm.logger.Info("acme.sh not found, installing acme.sh...")
	cmd := exec.Command("sh", "-c", fmt.Sprintf("curl -s https://get.acme.sh | sh -s email=%s && ln -sf /root/.acme.sh/acme.sh /usr/local/bin/acme.sh", sm.adminEmail))
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("install acme.sh failed: %s (%w)", string(out), err)
	}

	// Register account with LetsEncrypt if needed
	_ = exec.Command("acme.sh", "--register-account", "-m", sm.adminEmail, "--server", "letsencrypt").Run()

	return "/usr/local/bin/acme.sh", nil
}

// ObtainIPCertificate requests a public IP certificate from Let's Encrypt using shortlived ACME profile
func (sm *SSLManager) ObtainIPCertificate(ip string) (*CertificateInfo, error) {
	ip = strings.TrimSpace(ip)
	if !sm.IsIP(ip) {
		return nil, fmt.Errorf("'%s' is not a valid IP address", ip)
	}

	acmeBin, err := sm.ensureAcmeSh()
	if err != nil {
		return nil, fmt.Errorf("acme.sh unavailable: %w", err)
	}

	_ = os.MkdirAll(sm.acmeWebroot, 0755)

	targetDir := filepath.Join("/etc/ssl/bee-panel", ip)
	_ = os.MkdirAll(targetDir, 0700)
	targetCert := filepath.Join(targetDir, "fullchain.pem")
	targetKey := filepath.Join(targetDir, "privkey.pem")

	sm.logger.Info("Requesting Let's Encrypt shortlived IP certificate via acme.sh",
		"ip", ip,
		"webroot", sm.acmeWebroot,
	)

	// Issue shortlived certificate for bare IP
	issueArgs := []string{
		"--issue",
		"--server", "letsencrypt",
		"--cert-profile", "shortlived",
		"--days", "3",
		"-d", ip,
		"--webroot", sm.acmeWebroot,
	}

	cmd := exec.Command(acmeBin, issueArgs...)
	out, err := cmd.CombinedOutput()
	outStr := string(out)

	if err != nil && !strings.Contains(outStr, "Domains not changed") && !strings.Contains(outStr, "Skipping") {
		return nil, fmt.Errorf("acme.sh issue IP failed: %s (%w)", outStr, err)
	}

	// Install certs into targetDir
	installArgs := []string{
		"--install-cert",
		"-d", ip,
		"--fullchain-file", targetCert,
		"--key-file", targetKey,
		"--reloadcmd", "nginx -s reload",
	}
	installCmd := exec.Command(acmeBin, installArgs...)
	if iOut, iErr := installCmd.CombinedOutput(); iErr != nil {
		// Fallback: check if source certs exist in ~/.acme.sh/<ip>_ecc/
		srcCert := fmt.Sprintf("/root/.acme.sh/%s_ecc/fullchain.cer", ip)
		srcKey := fmt.Sprintf("/root/.acme.sh/%s_ecc/%s.key", ip, ip)
		cBytes, rErr1 := os.ReadFile(srcCert)
		kBytes, rErr2 := os.ReadFile(srcKey)
		if rErr1 == nil && rErr2 == nil {
			_ = os.WriteFile(targetCert, cBytes, 0644)
			_ = os.WriteFile(targetKey, kBytes, 0600)
		} else {
			return nil, fmt.Errorf("acme.sh install IP cert failed: %s (%w)", string(iOut), iErr)
		}
	}

	sm.logger.Info("Short-lived IP SSL certificate acquired successfully", "ip", ip, "cert", targetCert)
	return &CertificateInfo{CertPath: targetCert, KeyPath: targetKey}, nil
}

// RequestCertificate executes certbot in non-interactive webroot mode for domain names
func (sm *SSLManager) RequestCertificate(domain string) (certPath, keyPath string, err error) {
	if sm.IsIP(domain) {
		info, err := sm.ObtainIPCertificate(domain)
		if err != nil {
			return "", "", err
		}
		return info.CertPath, info.KeyPath, nil
	}

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
	if sm.IsIP(domain) {
		return sm.ObtainIPCertificate(domain)
	}
	cPath, kPath, err := sm.RequestCertificate(domain)
	if err != nil {
		return nil, err
	}
	return &CertificateInfo{CertPath: cPath, KeyPath: kPath}, nil
}

// StartAutoRenewWorker starts a background periodic worker to renew domain and IP certificates
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
				// 1. Certbot renewal for standard domains
				if _, err := exec.LookPath("certbot"); err == nil {
					_ = exec.Command("certbot", "renew", "--quiet").Run()
				}
				// 2. acme.sh renewal for short-lived IP certificates
				if _, err := exec.LookPath("acme.sh"); err == nil {
					_ = exec.Command("acme.sh", "--cron").Run()
				}
				// 3. Reload Nginx
				_ = exec.Command("nginx", "-s", "reload").Run()
				sm.logger.Info("SSL renew check completed successfully")
			}
		}
	}()
}
