package api

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/go-chi/chi/v5"

	"bee-panel/internal/core/provisioner"
	"bee-panel/internal/server/middleware"
	"bee-panel/internal/storage"
)

type AdminHandler struct {
	db             *storage.DB
	prov           *provisioner.Provisioner
	jwtSecret      string
	jwtExpiryHours int
}

func NewAdminHandler(db *storage.DB, prov *provisioner.Provisioner, jwtSecret string, jwtExpiryHours int) *AdminHandler {
	return &AdminHandler{
		db:             db,
		prov:           prov,
		jwtSecret:      jwtSecret,
		jwtExpiryHours: jwtExpiryHours,
	}
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type CreateTenantRequest struct {
	Username string `json:"username"`
}

type SystemMetrics struct {
	MemoryTotalMB     uint64 `json:"memory_total_mb"`
	MemoryUsedMB      uint64 `json:"memory_used_mb"`
	MemoryFreeMB      uint64 `json:"memory_free_mb"`
	SwapTotalMB       uint64 `json:"swap_total_mb"`
	SwapUsedMB        uint64 `json:"swap_used_mb"`
	DiskTotalGB       uint64 `json:"disk_total_gb"`
	DiskUsedGB        uint64 `json:"disk_used_gb"`
	DiskFreeGB        uint64 `json:"disk_free_gb"`
	ActiveTenantsCount int    `json:"active_tenants_count"`
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

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(AuthResponse{
		Token:    token,
		Username: admin.Username,
		Email:    admin.Email,
	})
}

func (h *AdminHandler) GetMetrics(w http.ResponseWriter, r *http.Request) {
	metrics := SystemMetrics{}

	// Memory & Swap from /proc/meminfo
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

	// Disk Stats for root filesystem
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

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(metrics)
}

func (h *AdminHandler) ListTenants(w http.ResponseWriter, r *http.Request) {
	tenants, err := h.db.ListTenants()
	if err != nil {
		http.Error(w, `{"error":"failed to fetch tenants"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(tenants)
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

	creds, err := h.prov.ProvisionTenant(req.Username)
	if err != nil {
		http.Error(w, `{"error":"provision failed: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	// Save to DB
	_, err = h.db.CreateTenant(creds.Username, creds.UID, creds.GID, creds.HomeDir, creds.DockerSocket)
	if err != nil {
		_ = h.prov.DeprovisionTenant(creds.Username, creds.UID)
		http.Error(w, `{"error":"failed to save tenant in db"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(creds)
}

func (h *AdminHandler) DeleteTenant(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")
	if username == "" {
		http.Error(w, `{"error":"username parameter required"}`, http.StatusBadRequest)
		return
	}

	if err := h.prov.DeprovisionTenant(username, 0); err != nil {
		http.Error(w, `{"error":"deprovision failed: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	_ = h.db.DeleteTenant(username)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "deleted", "username": username})
}
