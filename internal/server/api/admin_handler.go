package api

import (
	"bufio"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"

	"bee-panel/internal/config"
	"bee-panel/internal/core/docker"
	"bee-panel/internal/core/notification"
	"bee-panel/internal/core/provisioner"
	"bee-panel/internal/core/proxy"
	"bee-panel/internal/core/security"
	"bee-panel/internal/core/system"
	"bee-panel/internal/core/updater"
	"bee-panel/internal/server/middleware"
	"bee-panel/internal/storage"
)

type AdminHandler struct {
	cfg            *config.Config
	db             *storage.DB
	prov           *provisioner.Provisioner
	nginxMgr       *proxy.NginxManager
	sslMgr         *proxy.SSLManager
	dockerExp      *docker.DockerExplorer
	fwMgr          *security.FirewallManager
	f2bMgr         *security.Fail2banManager
	sshMgr         *system.SSHConfigManager
	updater        *updater.Updater
	jwtSecret      string
	jwtExpiryHours int
}

func NewAdminHandler(
	cfg *config.Config,
	db *storage.DB,
	prov *provisioner.Provisioner,
	nginxMgr *proxy.NginxManager,
	sslMgr *proxy.SSLManager,
	jwtSecret string,
	jwtExpiryHours int,
) *AdminHandler {
	return &AdminHandler{
		cfg:            cfg,
		db:             db,
		prov:           prov,
		nginxMgr:       nginxMgr,
		sslMgr:         sslMgr,
		dockerExp:      docker.NewDockerExplorer(),
		fwMgr:          security.NewFirewallManager(),
		f2bMgr:         security.NewFail2banManager(),
		sshMgr:         system.NewSSHConfigManager(),
		updater:        updater.NewUpdater(),
		jwtSecret:      jwtSecret,
		jwtExpiryHours: jwtExpiryHours,
	}
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type CreateTenantRequest struct {
	Username  string `json:"username"`
	Password  string `json:"password,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
}

type UpdateTenantStatusRequest struct {
	Status string `json:"status"` // active or suspended
}

type UpdateTenantPasswordRequest struct {
	Password string `json:"password"`
}

type UpdateTenantKeyRequest struct {
	PublicKey string `json:"public_key,omitempty"`
}

type SystemMetrics struct {
	CPUUsagePercent    float64 `json:"cpu_usage_percent"`
	CPUCores           int     `json:"cpu_cores"`
	LoadAverage        string  `json:"load_average"`
	UptimeSeconds      uint64  `json:"uptime_seconds"`
	MemoryTotalMB      uint64  `json:"memory_total_mb"`
	MemoryUsedMB       uint64  `json:"memory_used_mb"`
	MemoryFreeMB       uint64  `json:"memory_free_mb"`
	SwapTotalMB        uint64  `json:"swap_total_mb"`
	SwapUsedMB         uint64  `json:"swap_used_mb"`
	DiskTotalGB        uint64  `json:"disk_total_gb"`
	DiskUsedGB         uint64  `json:"disk_used_gb"`
	DiskFreeGB         uint64  `json:"disk_free_gb"`
	ActiveTenantsCount int     `json:"active_tenants_count"`
	ContainersCount    int     `json:"containers_count"`
	FirewallEnabled    bool    `json:"firewall_enabled"`
	Fail2banActive     bool    `json:"fail2ban_active"`
}

func (h *AdminHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request payload"}`, http.StatusBadRequest)
		return
	}

	admin, err := h.db.AuthenticateAdmin(req.Username, req.Password)
	if err != nil {
		http.Error(w, `{"error":"invalid username or password"}`, http.StatusUnauthorized)
		return
	}

	token, err := middleware.GenerateToken(admin.ID, admin.Username, "admin", h.jwtSecret, h.jwtExpiryHours)
	if err != nil {
		http.Error(w, `{"error":"failed to generate token"}`, http.StatusInternalServerError)
		return
	}

	// Trigger Telegram login alert asynchronously if enabled
	if h.cfg.Telegram.Enabled && h.cfg.Telegram.NotifyOnLogin {
		go func() {
			tg := notification.NewTelegramNotifier(h.cfg.Telegram.BotToken, h.cfg.Telegram.ChatID)
			_ = tg.Send(fmt.Sprintf("🔑 <b>Admin Login Alert</b>\nUser: <code>%s</code>\nTime: %s", admin.Username, time.Now().Format("2006-01-02 15:04:05")))
		}()
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(AuthResponse{
		Token:    token,
		Username: admin.Username,
		Email:    admin.Email,
	})
}

func readCPUSample() (idle, total uint64) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 5 && fields[0] == "cpu" {
			var vals []uint64
			for _, field := range fields[1:] {
				v, _ := strconv.ParseUint(field, 10, 64)
				vals = append(vals, v)
				total += v
			}
			if len(vals) >= 4 {
				idle = vals[3] // idle field
				if len(vals) >= 5 {
					idle += vals[4] // iowait field
				}
			}
		}
	}
	return
}

func (h *AdminHandler) GetMetrics(w http.ResponseWriter, r *http.Request) {
	metrics := SystemMetrics{
		CPUCores: runtime.NumCPU(),
	}

	// 1. CPU Usage Calculation (150ms delta)
	idle1, total1 := readCPUSample()
	time.Sleep(120 * time.Millisecond)
	idle2, total2 := readCPUSample()
	if total2 > total1 {
		totalDelta := float64(total2 - total1)
		idleDelta := float64(idle2 - idle1)
		usage := 100.0 * (1.0 - (idleDelta / totalDelta))
		if usage < 0 {
			usage = 0
		} else if usage > 100 {
			usage = 100
		}
		metrics.CPUUsagePercent = float64(int(usage*10)) / 10.0
	}

	// 2. Load Average
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		parts := strings.Fields(string(data))
		if len(parts) >= 3 {
			metrics.LoadAverage = fmt.Sprintf("%s, %s, %s", parts[0], parts[1], parts[2])
		}
	}

	// 3. Uptime
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		parts := strings.Fields(string(data))
		if len(parts) >= 1 {
			upFloat, _ := strconv.ParseFloat(parts[0], 64)
			metrics.UptimeSeconds = uint64(upFloat)
		}
	}

	// 4. Memory & Swap from /proc/meminfo
	if f, err := os.Open("/proc/meminfo"); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		var memTotal, memAvailable, swapTotal, swapFree uint64
		for scanner.Scan() {
			line := scanner.Text()
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				val, _ := strconv.ParseUint(fields[1], 10, 64)
				switch fields[0] {
				case "MemTotal:":
					memTotal = val / 1024
				case "MemAvailable:":
					memAvailable = val / 1024
				case "SwapTotal:":
					swapTotal = val / 1024
				case "SwapFree:":
					swapFree = val / 1024
				}
			}
		}
		metrics.MemoryTotalMB = memTotal
		metrics.MemoryFreeMB = memAvailable
		if memTotal > memAvailable {
			metrics.MemoryUsedMB = memTotal - memAvailable
		}
		metrics.SwapTotalMB = swapTotal
		if swapTotal > swapFree {
			metrics.SwapUsedMB = swapTotal - swapFree
		}
	}

	// 5. Disk Stats for root filesystem
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err == nil {
		totalBytes := stat.Blocks * uint64(stat.Bsize)
		freeBytes := stat.Bfree * uint64(stat.Bsize)
		metrics.DiskTotalGB = totalBytes / (1024 * 1024 * 1024)
		metrics.DiskFreeGB = freeBytes / (1024 * 1024 * 1024)
		if totalBytes > freeBytes {
			metrics.DiskUsedGB = (totalBytes - freeBytes) / (1024 * 1024 * 1024)
		}
	}

	tenants, _ := h.db.ListTenants()
	metrics.ActiveTenantsCount = len(tenants)

	// Count running containers
	containers, _ := h.dockerExp.ListAllContainers(tenants)
	metrics.ContainersCount = len(containers)

	// Quick Security checks
	if fwStat, err := h.fwMgr.Status(); err == nil {
		metrics.FirewallEnabled = fwStat.Enabled
	}
	if f2bStat, err := h.f2bMgr.Status(); err == nil {
		metrics.Fail2banActive = f2bStat.Active
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(metrics)
}

// --- Tenants Management ---

func (h *AdminHandler) ListTenants(w http.ResponseWriter, r *http.Request) {
	tenants, err := h.db.ListTenants()
	if err != nil {
		http.Error(w, `{"error":"failed to fetch tenants"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(tenants)
}

func (h *AdminHandler) GetTenant(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")
	t, err := h.db.GetTenant(username)
	if err != nil {
		http.Error(w, `{"error":"tenant not found"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(t)
}

func (h *AdminHandler) CreateTenant(w http.ResponseWriter, r *http.Request) {
	var req CreateTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request payload"}`, http.StatusBadRequest)
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" {
		http.Error(w, `{"error":"username is required"}`, http.StatusBadRequest)
		return
	}

	creds, err := h.prov.ProvisionTenantWithCustom(req.Username, req.Password, req.PublicKey)
	if err != nil {
		http.Error(w, `{"error":"provision failed: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	// Save to DB with credentials
	_, err = h.db.CreateTenantWithCredentials(
		creds.Username, creds.UID, creds.GID, creds.HomeDir, creds.DockerSocket,
		creds.Password, creds.PrivateKeyOpenSSH, creds.PublicKeyOpenSSH,
	)
	if err != nil {
		_ = h.prov.DeprovisionTenant(creds.Username, creds.UID)
		http.Error(w, `{"error":"failed to save tenant in db"}`, http.StatusInternalServerError)
		return
	}

	// Telegram notification
	if h.cfg.Telegram.Enabled && h.cfg.Telegram.NotifyOnTenantCreated {
		go func() {
			tg := notification.NewTelegramNotifier(h.cfg.Telegram.BotToken, h.cfg.Telegram.ChatID)
			_ = tg.Send(fmt.Sprintf("🚀 <b>New Tenant Created</b>\nUsername: <code>%s</code>\nUID: %d", creds.Username, creds.UID))
		}()
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(creds)
}

func (h *AdminHandler) UpdateTenantStatus(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")
	var req UpdateTenantStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request payload"}`, http.StatusBadRequest)
		return
	}

	t, err := h.db.GetTenant(username)
	if err != nil {
		http.Error(w, `{"error":"tenant not found"}`, http.StatusNotFound)
		return
	}

	if req.Status == "suspended" {
		if err := h.prov.SuspendTenant(t.Username, t.UID); err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}
	} else {
		if err := h.prov.ResumeTenant(t.Username, t.UID); err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}
	}

	_ = h.db.UpdateTenantStatus(username, req.Status)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": req.Status})
}

func (h *AdminHandler) UpdateTenantPassword(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")
	var req UpdateTenantPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Password == "" {
		http.Error(w, `{"error":"new password required"}`, http.StatusBadRequest)
		return
	}

	if err := h.prov.ChangePassword(username, req.Password); err != nil {
		http.Error(w, `{"error":"failed to change password: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	t, _ := h.db.GetTenant(username)
	_ = h.db.UpdateTenantCredentials(username, req.Password, t.PrivateKey, t.PublicKey)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "password updated successfully"})
}

func (h *AdminHandler) UpdateTenantSSHKey(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")
	var req UpdateTenantKeyRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	t, err := h.db.GetTenant(username)
	if err != nil {
		http.Error(w, `{"error":"tenant not found"}`, http.StatusNotFound)
		return
	}

	privKey, pubKey, err := h.prov.RotateSSHKey(t.Username, t.UID, t.GID, t.HomeDir, req.PublicKey)
	if err != nil {
		http.Error(w, `{"error":"failed to update ssh key: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	_ = h.db.UpdateTenantCredentials(username, t.PasswordPlain, privKey, pubKey)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"private_key": privKey,
		"public_key":  pubKey,
	})
}

func (h *AdminHandler) RestartTenantDocker(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")
	t, err := h.db.GetTenant(username)
	if err != nil {
		http.Error(w, `{"error":"tenant not found"}`, http.StatusNotFound)
		return
	}

	if err := h.prov.RestartTenantDocker(username, t.UID); err != nil {
		http.Error(w, `{"error":"restart docker failed: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "docker daemon restarted"})
}

func (h *AdminHandler) DeleteTenant(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")
	if username == "" {
		http.Error(w, `{"error":"username parameter required"}`, http.StatusBadRequest)
		return
	}

	t, _ := h.db.GetTenant(username)
	uid := 0
	if t != nil {
		uid = t.UID
	}

	if err := h.prov.DeprovisionTenant(username, uid); err != nil {
		http.Error(w, `{"error":"deprovision failed: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	_ = h.db.DeleteTenant(username)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "deleted", "username": username})
}

// --- Docker Containers Management ---

func (h *AdminHandler) ListContainers(w http.ResponseWriter, r *http.Request) {
	tenants, _ := h.db.ListTenants()
	containers, err := h.dockerExp.ListAllContainers(tenants)
	if err != nil {
		http.Error(w, `{"error":"failed to list containers: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(containers)
}

func (h *AdminHandler) findSocketForTenant(tenant string) string {
	if tenant == "system-root" {
		return "/var/run/docker.sock"
	}
	t, err := h.db.GetTenant(tenant)
	if err == nil && t != nil && t.DockerSocket != "" {
		return t.DockerSocket
	}
	return ""
}

func (h *AdminHandler) StartContainer(w http.ResponseWriter, r *http.Request) {
	tenant := chi.URLParam(r, "tenant")
	id := chi.URLParam(r, "id")
	socket := h.findSocketForTenant(tenant)
	if socket == "" {
		http.Error(w, `{"error":"tenant docker socket not found"}`, http.StatusBadRequest)
		return
	}
	if err := h.dockerExp.StartContainer(socket, id); err != nil {
		http.Error(w, `{"error":"start failed: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "container started"})
}

func (h *AdminHandler) StopContainer(w http.ResponseWriter, r *http.Request) {
	tenant := chi.URLParam(r, "tenant")
	id := chi.URLParam(r, "id")
	socket := h.findSocketForTenant(tenant)
	if socket == "" {
		http.Error(w, `{"error":"tenant docker socket not found"}`, http.StatusBadRequest)
		return
	}
	if err := h.dockerExp.StopContainer(socket, id); err != nil {
		http.Error(w, `{"error":"stop failed: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "container stopped"})
}

func (h *AdminHandler) RestartContainer(w http.ResponseWriter, r *http.Request) {
	tenant := chi.URLParam(r, "tenant")
	id := chi.URLParam(r, "id")
	socket := h.findSocketForTenant(tenant)
	if socket == "" {
		http.Error(w, `{"error":"tenant docker socket not found"}`, http.StatusBadRequest)
		return
	}
	if err := h.dockerExp.RestartContainer(socket, id); err != nil {
		http.Error(w, `{"error":"restart failed: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "container restarted"})
}

func (h *AdminHandler) GetContainerLogs(w http.ResponseWriter, r *http.Request) {
	tenant := chi.URLParam(r, "tenant")
	id := chi.URLParam(r, "id")
	linesStr := r.URL.Query().Get("lines")
	lines := 200
	if l, err := strconv.Atoi(linesStr); err == nil && l > 0 {
		lines = l
	}

	socket := h.findSocketForTenant(tenant)
	if socket == "" {
		http.Error(w, `{"error":"tenant docker socket not found"}`, http.StatusBadRequest)
		return
	}

	logs, err := h.dockerExp.GetContainerLogs(socket, id, lines)
	if err != nil {
		http.Error(w, `{"error":"get logs failed: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"logs": logs})
}

// --- Domains Management ---

type BindDomainAdminRequest struct {
	TenantID            int64  `json:"tenant_id"`
	Domain              string `json:"domain"`
	ExternalPort        int    `json:"external_port"`
	TargetContainerPort int    `json:"target_container_port"`
	EnableSSL           bool   `json:"enable_ssl"`
}

func (h *AdminHandler) ListDomains(w http.ResponseWriter, r *http.Request) {
	domains, err := h.db.ListDomainMappingsWithTenant()
	if err != nil {
		http.Error(w, `{"error":"failed to list domains"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(domains)
}

func cleanDomainFQDN(domain string) string {
	d := strings.ToLower(strings.TrimSpace(domain))
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimPrefix(d, "https://")
	if idx := strings.Index(d, "/"); idx != -1 {
		d = d[:idx]
	}
	if idx := strings.Index(d, ":"); idx != -1 {
		d = d[:idx]
	}
	return strings.TrimSpace(d)
}

func (h *AdminHandler) BindDomain(w http.ResponseWriter, r *http.Request) {
	var req BindDomainAdminRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request payload"}`, http.StatusBadRequest)
		return
	}
	req.Domain = cleanDomainFQDN(req.Domain)
	if req.Domain == "" || req.TargetContainerPort <= 0 {
		http.Error(w, `{"error":"domain and target port are required"}`, http.StatusBadRequest)
		return
	}

	if req.ExternalPort <= 0 {
		if req.EnableSSL {
			req.ExternalPort = 443
		} else {
			req.ExternalPort = 80
		}
	}

	var certPath, keyPath string
	if req.EnableSSL {
		cert, err := h.sslMgr.ObtainCertificate(req.Domain)
		if err != nil {
			http.Error(w, `{"error":"ssl acquisition failed: `+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}
		certPath = cert.CertPath
		keyPath = cert.KeyPath
	}

	// Apply Nginx VHost
	vhost := &proxy.VHostConfig{
		Domain:              req.Domain,
		ExternalPort:        req.ExternalPort,
		TargetContainerPort: req.TargetContainerPort,
		EnableSSL:           req.EnableSSL,
		SSLCertPath:         certPath,
		SSLKeyPath:          keyPath,
	}
	if err := h.nginxMgr.ApplyVHost(vhost); err != nil {
		http.Error(w, `{"error":"nginx vhost failed: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	mapping := &storage.DomainMapping{
		TenantID:            req.TenantID,
		Domain:              req.Domain,
		ExternalPort:        req.ExternalPort,
		TargetContainerPort: req.TargetContainerPort,
		EnableSSL:           req.EnableSSL,
		SSLCertPath:         certPath,
		SSLKeyPath:          keyPath,
	}
	if err := h.db.SaveDomainMapping(mapping); err != nil {
		_ = h.nginxMgr.RemoveVHost(req.Domain)
		http.Error(w, `{"error":"failed to save domain in database"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(mapping)
}

func (h *AdminHandler) UpdateDomain(w http.ResponseWriter, r *http.Request) {
	domain := chi.URLParam(r, "domain")
	var req struct {
		TargetContainerPort int  `json:"target_container_port"`
		EnableSSL           bool `json:"enable_ssl"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid payload"}`, http.StatusBadRequest)
		return
	}

	mapping, err := h.db.GetDomainMapping(domain)
	if err != nil {
		http.Error(w, `{"error":"domain not found"}`, http.StatusNotFound)
		return
	}

	certPath := mapping.SSLCertPath
	keyPath := mapping.SSLKeyPath

	if req.EnableSSL && (certPath == "" || keyPath == "") {
		cert, err := h.sslMgr.ObtainCertificate(domain)
		if err != nil {
			http.Error(w, `{"error":"ssl issuance failed: `+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}
		certPath = cert.CertPath
		keyPath = cert.KeyPath
	}

	vhost := &proxy.VHostConfig{
		Domain:              domain,
		ExternalPort:        mapping.ExternalPort,
		TargetContainerPort: req.TargetContainerPort,
		EnableSSL:           req.EnableSSL,
		SSLCertPath:         certPath,
		SSLKeyPath:          keyPath,
	}
	if err := h.nginxMgr.ApplyVHost(vhost); err != nil {
		http.Error(w, `{"error":"nginx apply failed: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	_ = h.db.UpdateDomainMapping(domain, req.TargetContainerPort, req.EnableSSL, certPath, keyPath)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "domain updated successfully"})
}

func (h *AdminHandler) DeleteDomain(w http.ResponseWriter, r *http.Request) {
	domain := chi.URLParam(r, "domain")
	_ = h.nginxMgr.RemoveVHost(domain)
	_ = h.db.DeleteDomainMapping(domain)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "deleted", "domain": domain})
}

func (h *AdminHandler) ForceRenewSSL(w http.ResponseWriter, r *http.Request) {
	domain := chi.URLParam(r, "domain")
	cert, err := h.sslMgr.ObtainCertificate(domain)
	if err != nil {
		http.Error(w, `{"error":"ssl renewal failed: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	mapping, _ := h.db.GetDomainMapping(domain)
	if mapping != nil {
		_ = h.db.UpdateDomainMapping(domain, mapping.TargetContainerPort, true, cert.CertPath, cert.KeyPath)
		vhost := &proxy.VHostConfig{
			Domain:              domain,
			ExternalPort:        mapping.ExternalPort,
			TargetContainerPort: mapping.TargetContainerPort,
			EnableSSL:           true,
			SSLCertPath:         cert.CertPath,
			SSLKeyPath:          cert.KeyPath,
		}
		_ = h.nginxMgr.ApplyVHost(vhost)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "ssl renewed successfully"})
}

func (h *AdminHandler) UploadCustomSSL(w http.ResponseWriter, r *http.Request) {
	domain := chi.URLParam(r, "domain")
	var req struct {
		CertContent string `json:"cert_content"`
		KeyContent  string `json:"key_content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.CertContent == "" || req.KeyContent == "" {
		http.Error(w, `{"error":"cert and key content required"}`, http.StatusBadRequest)
		return
	}

	certPath, keyPath, err := h.nginxMgr.SaveCustomSSL(domain, req.CertContent, req.KeyContent)
	if err != nil {
		http.Error(w, `{"error":"save custom ssl failed: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	mapping, _ := h.db.GetDomainMapping(domain)
	if mapping != nil {
		_ = h.db.UpdateDomainMapping(domain, mapping.TargetContainerPort, true, certPath, keyPath)
		vhost := &proxy.VHostConfig{
			Domain:              domain,
			ExternalPort:        mapping.ExternalPort,
			TargetContainerPort: mapping.TargetContainerPort,
			EnableSSL:           true,
			SSLCertPath:         certPath,
			SSLKeyPath:          keyPath,
		}
		if err := h.nginxMgr.ApplyVHost(vhost); err != nil {
			http.Error(w, `{"error":"apply custom ssl failed: `+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "custom ssl certificate applied"})
}

func (h *AdminHandler) GetDomainLogs(w http.ResponseWriter, r *http.Request) {
	domain := chi.URLParam(r, "domain")
	logType := r.URL.Query().Get("type")
	linesStr := r.URL.Query().Get("lines")
	lines := 100
	if l, err := strconv.Atoi(linesStr); err == nil && l > 0 {
		lines = l
	}

	logLines, err := h.nginxMgr.GetDomainLogs(domain, logType, lines)
	if err != nil {
		http.Error(w, `{"error":"failed to read logs: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"domain": domain,
		"type":   logType,
		"lines":  logLines,
	})
}

// --- Security (Firewall & Fail2ban) ---

func (h *AdminHandler) GetFirewallStatus(w http.ResponseWriter, r *http.Request) {
	status, err := h.fwMgr.Status()
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}

func (h *AdminHandler) ToggleFirewall(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enable bool `json:"enable"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if err := h.fwMgr.Toggle(req.Enable); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"enabled": req.Enable})
}

func (h *AdminHandler) AddFirewallRule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Port     string `json:"port"`
		Protocol string `json:"protocol"`
		Action   string `json:"action"`
		From     string `json:"from"`
		Comment  string `json:"comment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Port == "" {
		http.Error(w, `{"error":"port is required"}`, http.StatusBadRequest)
		return
	}

	if err := h.fwMgr.AddRule(req.Port, req.Protocol, req.Action, req.From, req.Comment); err != nil {
		http.Error(w, `{"error":"add rule failed: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "firewall rule added"})
}

func (h *AdminHandler) DeleteFirewallRule(w http.ResponseWriter, r *http.Request) {
	numStr := chi.URLParam(r, "number")
	num, err := strconv.Atoi(numStr)
	if err != nil {
		http.Error(w, `{"error":"invalid rule number"}`, http.StatusBadRequest)
		return
	}
	if err := h.fwMgr.DeleteRule(num); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "firewall rule deleted"})
}

func (h *AdminHandler) GetFail2banStatus(w http.ResponseWriter, r *http.Request) {
	status, err := h.f2bMgr.Status()
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}

func (h *AdminHandler) BanFail2banIP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Jail string `json:"jail"`
		IP   string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		http.Error(w, `{"error":"ip address is required"}`, http.StatusBadRequest)
		return
	}
	if err := h.f2bMgr.BanIP(req.Jail, req.IP); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "ip banned successfully"})
}

func (h *AdminHandler) UnbanFail2banIP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Jail string `json:"jail"`
		IP   string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		http.Error(w, `{"error":"ip address is required"}`, http.StatusBadRequest)
		return
	}
	if err := h.f2bMgr.UnbanIP(req.Jail, req.IP); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "ip unbanned successfully"})
}

func (h *AdminHandler) GetFail2banConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.f2bMgr.GetConfig()
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cfg)
}

func (h *AdminHandler) UpdateFail2banConfig(w http.ResponseWriter, r *http.Request) {
	var req security.Fail2banConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid fail2ban config json"}`, http.StatusBadRequest)
		return
	}
	if err := h.f2bMgr.UpdateConfig(&req); err != nil {
		http.Error(w, `{"error":"failed to update fail2ban config: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "fail2ban configuration updated and service reloaded"})
}

// --- Settings, Telegram, SSH & Panel Domain ---

func (h *AdminHandler) SetPanelDomain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
		SSL    bool   `json:"ssl"`
		Email  string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Domain) == "" {
		http.Error(w, `{"error":"domain is required"}`, http.StatusBadRequest)
		return
	}
	domain := cleanDomainFQDN(req.Domain)
	if domain == "" {
		http.Error(w, `{"error":"invalid domain format"}`, http.StatusBadRequest)
		return
	}

	// Obtain SSL if requested
	sslCertPath := ""
	sslKeyPath := ""
	if req.SSL {
		// First apply plain HTTP vhost so ACME challenge directory works
		if err := h.nginxMgr.ApplyPanelVHost(domain, h.cfg.Server.AdminPort, false, "", ""); err != nil {
			http.Error(w, `{"error":"failed to prepare http panel vhost: `+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}

		// Try obtaining certificate via Let's Encrypt
		certInfo, err := h.sslMgr.ObtainCertificate(domain)
		if err != nil {
			http.Error(w, `{"error":"failed to obtain SSL certificate for `+domain+`: `+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}
		sslCertPath = certInfo.CertPath
		sslKeyPath = certInfo.KeyPath
	}

	// Apply final vhost
	if err := h.nginxMgr.ApplyPanelVHost(domain, h.cfg.Server.AdminPort, req.SSL, sslCertPath, sslKeyPath); err != nil {
		http.Error(w, `{"error":"failed to apply panel vhost: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	h.cfg.Server.PanelDomain = domain
	h.cfg.Server.PanelSSL = req.SSL
	_ = config.SaveConfig("", h.cfg)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"message":      "Panel domain bound successfully",
		"panel_domain": domain,
		"panel_ssl":    req.SSL,
	})
}

func (h *AdminHandler) RemovePanelDomain(w http.ResponseWriter, r *http.Request) {
	if err := h.nginxMgr.RemovePanelVHost(); err != nil {
		http.Error(w, `{"error":"failed to remove panel domain vhost: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	h.cfg.Server.PanelDomain = ""
	h.cfg.Server.PanelSSL = false
	_ = config.SaveConfig("", h.cfg)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message": "Panel domain binding removed successfully",
	})
}

func (h *AdminHandler) detectPublicIP() string {
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("https://api.ipify.org")
	if err == nil {
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		ip := strings.TrimSpace(string(b))
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	if h.cfg.Server.PanelIP != "" && net.ParseIP(h.cfg.Server.PanelIP) != nil {
		return h.cfg.Server.PanelIP
	}
	return ""
}

func (h *AdminHandler) IssueIPSSL(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP string `json:"ip"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	targetIP := strings.TrimSpace(req.IP)
	if targetIP == "" {
		targetIP = h.detectPublicIP()
	}
	if targetIP == "" || !h.sslMgr.IsIP(targetIP) {
		http.Error(w, `{"error":"valid public IPv4 address is required"}`, http.StatusBadRequest)
		return
	}

	// 1. First ensure plain HTTP vhost exists to satisfy Let's Encrypt HTTP-01 challenge
	if err := h.nginxMgr.ApplyPanelVHost(targetIP, h.cfg.Server.AdminPort, false, "", ""); err != nil {
		http.Error(w, `{"error":"failed to prepare http challenge vhost: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	// 2. Request shortlived Let's Encrypt IP certificate via acme.sh
	certInfo, err := h.sslMgr.ObtainIPCertificate(targetIP)
	if err != nil {
		http.Error(w, `{"error":"failed to obtain Let's Encrypt IP certificate: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	// 3. Apply HTTPS portless Nginx vhost on port 443 proxying to AdminPort 8443
	if err := h.nginxMgr.ApplyPanelVHost(targetIP, h.cfg.Server.AdminPort, true, certInfo.CertPath, certInfo.KeyPath); err != nil {
		http.Error(w, `{"error":"failed to apply https panel vhost: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	h.cfg.Server.PanelIP = targetIP
	h.cfg.Server.PanelIPSSL = true
	_ = config.SaveConfig("", h.cfg)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"message":   "Let's Encrypt IP SSL issued and HTTPS port 443 active",
		"ip":        targetIP,
		"cert_path": certInfo.CertPath,
		"key_path":  certInfo.KeyPath,
		"https_url": fmt.Sprintf("https://%s/", targetIP),
		"status":    "active",
	})
}

func (h *AdminHandler) GetIPSSLStatus(w http.ResponseWriter, r *http.Request) {
	ip := h.cfg.Server.PanelIP
	if ip == "" {
		ip = h.detectPublicIP()
	}

	res := map[string]interface{}{
		"ip":        ip,
		"active":    false,
		"expires":   "",
		"cert_path": "",
	}

	if ip != "" {
		certPath := filepath.Join("/etc/ssl/bee-panel", ip, "fullchain.pem")
		if data, err := os.ReadFile(certPath); err == nil {
			block, _ := pem.Decode(data)
			if block != nil {
				if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
					res["active"] = time.Now().Before(cert.NotAfter)
					res["expires"] = cert.NotAfter.Format("2006-01-02 15:04:05 UTC")
					res["issuer"] = cert.Issuer.CommonName
					res["cert_path"] = certPath
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

func (h *AdminHandler) GetSettings(w http.ResponseWriter, r *http.Request) {
	sshPort := h.sshMgr.GetCurrentSSHPort()
	publicIP := h.detectPublicIP()
	res := map[string]interface{}{
		"config":        h.cfg,
		"ssh_port":      sshPort,
		"public_ip":     publicIP,
		"ip_ssl_active": h.cfg.Server.PanelIPSSL,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

func (h *AdminHandler) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	var newCfg config.Config
	if err := json.NewDecoder(r.Body).Decode(&newCfg); err != nil {
		http.Error(w, `{"error":"invalid settings json"}`, http.StatusBadRequest)
		return
	}

	h.cfg.Server = newCfg.Server
	h.cfg.Ports = newCfg.Ports
	h.cfg.Proxy = newCfg.Proxy
	h.cfg.Docker = newCfg.Docker
	h.cfg.Telegram = newCfg.Telegram

	if err := config.SaveConfig("", h.cfg); err != nil {
		http.Error(w, `{"error":"failed to save settings: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "settings saved successfully"})
}

func (h *AdminHandler) SendTelegramTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BotToken string `json:"bot_token"`
		ChatID   string `json:"chat_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	token := req.BotToken
	if token == "" {
		token = h.cfg.Telegram.BotToken
	}
	chatID := req.ChatID
	if chatID == "" {
		chatID = h.cfg.Telegram.ChatID
	}

	tg := notification.NewTelegramNotifier(token, chatID)
	if err := tg.SendTest(); err != nil {
		http.Error(w, `{"error":"telegram test failed: `+err.Error()+`"}`, http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "telegram test notification sent successfully"})
}

func (h *AdminHandler) GetSSHPort(w http.ResponseWriter, r *http.Request) {
	port := h.sshMgr.GetCurrentSSHPort()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]int{"ssh_port": port})
}

func (h *AdminHandler) ChangeSSHPort(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Port int `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Port <= 0 {
		http.Error(w, `{"error":"valid port number is required"}`, http.StatusBadRequest)
		return
	}

	if err := h.sshMgr.ChangeSSHPort(req.Port, h.fwMgr); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"message":  "SSH port changed and service reloaded successfully",
		"ssh_port": req.Port,
	})
}

func (h *AdminHandler) UpdateAdminProfile(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetAuthUser(r)
	if claims == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" || req.Email == "" {
		http.Error(w, `{"error":"username and email required"}`, http.StatusBadRequest)
		return
	}

	if err := h.db.UpdateAdminProfile(claims.UserID, req.Username, req.Email); err != nil {
		http.Error(w, `{"error":"profile update failed: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "admin profile updated successfully"})
}

func (h *AdminHandler) UpdateAdminPassword(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetAuthUser(r)
	if claims == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var req struct {
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.NewPassword) < 8 {
		http.Error(w, `{"error":"password must be at least 8 characters"}`, http.StatusBadRequest)
		return
	}

	if err := h.db.UpdateAdminPassword(claims.UserID, req.NewPassword); err != nil {
		http.Error(w, `{"error":"password update failed: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "admin password updated successfully"})
}

// --- Updates ---

func (h *AdminHandler) GetVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"version":    updater.CurrentVersion,
		"go_version": runtime.Version(),
		"arch":       runtime.GOARCH,
		"os":         runtime.GOOS,
	})
}

func (h *AdminHandler) CheckUpdate(w http.ResponseWriter, r *http.Request) {
	info, err := h.updater.CheckUpdate()
	if err != nil {
		http.Error(w, `{"error":"failed to check update: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(info)
}

func (h *AdminHandler) TriggerUpdate(w http.ResponseWriter, r *http.Request) {
	if err := h.updater.PerformSelfUpdate(); err != nil {
		http.Error(w, `{"error":"self update failed: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message": "Update downloaded and verified. Daemon is restarting...",
	})
}
