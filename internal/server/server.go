package server

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"golang.org/x/sync/errgroup"

	"bee-panel/internal/config"
	"bee-panel/internal/core/provisioner"
	"bee-panel/internal/core/proxy"
	"bee-panel/internal/server/api"
	serverMiddleware "bee-panel/internal/server/middleware"
	"bee-panel/internal/storage"
)

type Server struct {
	cfg        *config.Config
	db         *storage.DB
	prov       *provisioner.Provisioner
	nginxMgr   *proxy.NginxManager
	sslMgr     *proxy.SSLManager
	adminFS    fs.FS
	userFS     fs.FS
	logger     *slog.Logger
	httpServer *http.Server
}

type DualServer = Server

func NewDualServer(
	cfg *config.Config,
	db *storage.DB,
	prov *provisioner.Provisioner,
	nginxMgr *proxy.NginxManager,
	sslMgr *proxy.SSLManager,
	adminFS fs.FS,
	userFS fs.FS,
	logger *slog.Logger,
) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		cfg:      cfg,
		db:       db,
		prov:     prov,
		nginxMgr: nginxMgr,
		sslMgr:   sslMgr,
		adminFS:  adminFS,
		userFS:   userFS,
		logger:   logger,
	}
}

func (s *Server) Start(ctx context.Context) error {
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Unified Router on single port
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	setupH := api.NewSetupHandler(s.db, s.cfg.Server.JWTSecret, s.cfg.Server.JWTExpiryHours)
	adminH := api.NewAdminHandler(s.cfg, s.db, s.prov, s.nginxMgr, s.sslMgr, s.cfg.Server.JWTSecret, s.cfg.Server.JWTExpiryHours)
	userH := api.NewUserHandler(s.db, s.nginxMgr, s.sslMgr)

	r.Route("/api", func(apiR chi.Router) {
		apiR.Get("/health", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","panel":"bee-panel"}`))
		})

		apiR.Route("/setup", func(sr chi.Router) {
			sr.Get("/status", setupH.GetStatus)
			sr.Post("/register", setupH.RegisterInitialAdmin)
		})

		apiR.Post("/admin/login", adminH.Login)

		// Developer User Portal APIs
		apiR.Get("/user/domains", userH.ListDomains)
		apiR.Post("/user/domains", userH.BindDomain)
		apiR.Delete("/user/domains/{domain}", userH.DeleteDomain)
		apiR.Get("/user/domains/{domain}/logs", userH.GetDomainLogs)
		apiR.Post("/user/domains/{domain}/renew-ssl", userH.RenewSSL)

		// Protected Admin Routes
		apiR.Group(func(pr chi.Router) {
			pr.Use(serverMiddleware.JWTAuthMiddleware(s.cfg.Server.JWTSecret))

			// Metrics & System
			pr.Get("/admin/system/metrics", adminH.GetMetrics)
			pr.Get("/admin/system/version", adminH.GetVersion)
			pr.Post("/admin/system/check-update", adminH.CheckUpdate)
			pr.Post("/admin/system/update", adminH.TriggerUpdate)

			// Tenants (Users)
			pr.Get("/admin/tenants", adminH.ListTenants)
			pr.Post("/admin/tenants", adminH.CreateTenant)
			pr.Get("/admin/tenants/{username}", adminH.GetTenant)
			pr.Put("/admin/tenants/{username}/status", adminH.UpdateTenantStatus)
			pr.Put("/admin/tenants/{username}/password", adminH.UpdateTenantPassword)
			pr.Put("/admin/tenants/{username}/keys", adminH.UpdateTenantSSHKey)
			pr.Post("/admin/tenants/{username}/restart-docker", adminH.RestartTenantDocker)
			pr.Delete("/admin/tenants/{username}", adminH.DeleteTenant)

			// Docker Containers Explorer
			pr.Get("/admin/docker/containers", adminH.ListContainers)
			pr.Post("/admin/docker/containers/{tenant}/{id}/start", adminH.StartContainer)
			pr.Post("/admin/docker/containers/{tenant}/{id}/stop", adminH.StopContainer)
			pr.Post("/admin/docker/containers/{tenant}/{id}/restart", adminH.RestartContainer)
			pr.Get("/admin/docker/containers/{tenant}/{id}/logs", adminH.GetContainerLogs)

			// Domains & Proxy Management
			pr.Get("/admin/domains", adminH.ListDomains)
			pr.Post("/admin/domains", adminH.BindDomain)
			pr.Put("/admin/domains/{domain}", adminH.UpdateDomain)
			pr.Delete("/admin/domains/{domain}", adminH.DeleteDomain)
			pr.Post("/admin/domains/{domain}/ssl/renew", adminH.ForceRenewSSL)
			pr.Post("/admin/domains/{domain}/ssl/custom", adminH.UploadCustomSSL)
			pr.Get("/admin/domains/{domain}/logs", adminH.GetDomainLogs)

			// Security (Firewall & Fail2ban & IP SSL)
			pr.Get("/admin/security/firewall/status", adminH.GetFirewallStatus)
			pr.Post("/admin/security/firewall/toggle", adminH.ToggleFirewall)
			pr.Post("/admin/security/firewall/rules", adminH.AddFirewallRule)
			pr.Delete("/admin/security/firewall/rules/{number}", adminH.DeleteFirewallRule)
			pr.Get("/admin/security/fail2ban/status", adminH.GetFail2banStatus)
			pr.Get("/admin/security/fail2ban/config", adminH.GetFail2banConfig)
			pr.Put("/admin/security/fail2ban/config", adminH.UpdateFail2banConfig)
			pr.Post("/admin/security/fail2ban/ban", adminH.BanFail2banIP)
			pr.Post("/admin/security/fail2ban/unban", adminH.UnbanFail2banIP)
			pr.Post("/admin/security/ssl/issue-ip", adminH.IssueIPSSL)
			pr.Get("/admin/security/ssl/ip-status", adminH.GetIPSSLStatus)

			// Settings, Telegram, SSH & Panel Domain
			pr.Get("/admin/settings", adminH.GetSettings)
			pr.Put("/admin/settings", adminH.UpdateSettings)
			pr.Post("/admin/settings/telegram/test", adminH.SendTelegramTest)
			pr.Get("/admin/settings/ssh/port", adminH.GetSSHPort)
			pr.Put("/admin/settings/ssh/port", adminH.ChangeSSHPort)
			pr.Post("/admin/settings/panel-domain", adminH.SetPanelDomain)
			pr.Delete("/admin/settings/panel-domain", adminH.RemovePanelDomain)
			pr.Put("/admin/settings/admin/profile", adminH.UpdateAdminProfile)
			pr.Put("/admin/settings/admin/password", adminH.UpdateAdminPassword)
		})
	})

	// Mount Developer Portal at /portal and /developer
	if s.userFS != nil {
		s.setupSubSPA(r, "/portal", s.userFS)
		r.Get("/developer", func(w http.ResponseWriter, req *http.Request) {
			http.Redirect(w, req, "/portal", http.StatusMovedPermanently)
		})
		r.Get("/developer/*", func(w http.ResponseWriter, req *http.Request) {
			http.Redirect(w, req, "/portal", http.StatusMovedPermanently)
		})
	}

	// Mount Admin Console SPA at /*
	if s.adminFS != nil {
		s.setupSPA(r, s.adminFS)
	}

	listenAddr := fmt.Sprintf("%s:%d", s.cfg.Server.Host, s.cfg.Server.AdminPort)
	s.httpServer = &http.Server{
		Addr:         listenAddr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	g, gCtx := errgroup.WithContext(ctx)

	// Run Unified Server
	g.Go(func() error {
		s.logger.Info("Starting Bee Panel Unified Server", "addr", s.httpServer.Addr)
		if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("server error: %w", err)
		}
		return nil
	})

	// Graceful Shutdown Handler
	g.Go(func() error {
		<-gCtx.Done()
		s.logger.Info("Received termination signal. Shutting down server gracefully...")

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()

		return s.httpServer.Shutdown(shutdownCtx)
	})

	return g.Wait()
}

func (s *Server) setupSubSPA(r *chi.Mux, prefix string, staticFS fs.FS) {
	fileServer := http.FileServer(http.FS(staticFS))
	indexData, _ := fs.ReadFile(staticFS, "index.html")

	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		subPath := strings.TrimPrefix(req.URL.Path, prefix)
		subPath = strings.TrimPrefix(subPath, "/")
		if subPath == "" || subPath == "index.html" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(indexData)
			return
		}

		if _, err := fs.Stat(staticFS, subPath); err != nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(indexData)
			return
		}

		req.URL.Path = "/" + subPath
		fileServer.ServeHTTP(w, req)
	})

	r.Handle(prefix, handler)
	r.Handle(prefix+"/*", handler)
}

func (s *Server) setupSPA(r *chi.Mux, staticFS fs.FS) {
	fileServer := http.FileServer(http.FS(staticFS))
	indexData, _ := fs.ReadFile(staticFS, "index.html")

	r.Handle("/*", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		path := strings.TrimPrefix(req.URL.Path, "/")
		if path == "" || path == "index.html" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(indexData)
			return
		}

		if _, err := fs.Stat(staticFS, path); err != nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(indexData)
			return
		}
		fileServer.ServeHTTP(w, req)
	}))
}
