package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"bee-panel/internal/core/proxy"
	"bee-panel/internal/storage"
)

type UserHandler struct {
	db       *storage.DB
	nginxMgr *proxy.NginxManager
	sslMgr   *proxy.SSLManager
}

func NewUserHandler(db *storage.DB, nginxMgr *proxy.NginxManager, sslMgr *proxy.SSLManager) *UserHandler {
	return &UserHandler{
		db:       db,
		nginxMgr: nginxMgr,
		sslMgr:   sslMgr,
	}
}

type BindDomainRequest struct {
	Domain              string `json:"domain"`
	ExternalPort        int    `json:"external_port"`
	TargetContainerPort int    `json:"target_container_port"`
	EnableSSL           bool   `json:"enable_ssl"`
}

func (h *UserHandler) ListDomains(w http.ResponseWriter, r *http.Request) {
	domains, err := h.db.ListDomainMappings(0)
	if err != nil {
		http.Error(w, `{"error":"failed to fetch domain mappings"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(domains)
}

func (h *UserHandler) BindDomain(w http.ResponseWriter, r *http.Request) {
	var req BindDomainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request payload"}`, http.StatusBadRequest)
		return
	}

	req.Domain = strings.ToLower(strings.TrimSpace(req.Domain))
	if req.Domain == "" || req.TargetContainerPort <= 0 {
		http.Error(w, `{"error":"domain and target_container_port are required"}`, http.StatusBadRequest)
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
		// First apply HTTP vhost so ACME challenge webroot is reachable
		tempHTTPVhost := &proxy.VHostConfig{
			Domain:              req.Domain,
			ExternalPort:        80,
			TargetContainerPort: req.TargetContainerPort,
			EnableSSL:           false,
		}
		if err := h.nginxMgr.ApplyVHost(tempHTTPVhost); err != nil {
			http.Error(w, `{"error":"failed to prepare http challenge vhost: `+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}

		var err error
		certPath, keyPath, err = h.sslMgr.RequestCertificate(req.Domain)
		if err != nil {
			_ = h.nginxMgr.RemoveVHost(req.Domain)
			http.Error(w, `{"error":"ssl certificate request failed: `+err.Error()+`"}`, http.StatusBadRequest)
			return
		}
	}

	vhostCfg := &proxy.VHostConfig{
		Domain:              req.Domain,
		ExternalPort:        req.ExternalPort,
		TargetContainerPort: req.TargetContainerPort,
		EnableSSL:           req.EnableSSL,
		SSLCertPath:         certPath,
		SSLKeyPath:          keyPath,
	}

	if err := h.nginxMgr.ApplyVHost(vhostCfg); err != nil {
		http.Error(w, `{"error":"failed to apply nginx vhost: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	mapping := &storage.DomainMapping{
		TenantID:            1,
		Domain:              req.Domain,
		ExternalPort:        req.ExternalPort,
		TargetContainerPort: req.TargetContainerPort,
		EnableSSL:           req.EnableSSL,
		SSLCertPath:         certPath,
		SSLKeyPath:          keyPath,
	}

	if err := h.db.SaveDomainMapping(mapping); err != nil {
		_ = h.nginxMgr.RemoveVHost(req.Domain)
		http.Error(w, `{"error":"failed to save mapping to database: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(mapping)
}

func (h *UserHandler) DeleteDomain(w http.ResponseWriter, r *http.Request) {
	domain := chi.URLParam(r, "domain")
	if domain == "" {
		http.Error(w, `{"error":"domain parameter required"}`, http.StatusBadRequest)
		return
	}

	_ = h.nginxMgr.RemoveVHost(domain)
	_ = h.db.DeleteDomainMapping(domain)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "deleted", "domain": domain})
}
