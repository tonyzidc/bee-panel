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

type DualServer struct {
	cfg         *config.Config
	db          *storage.DB
	prov        *provisioner.Provisioner
	nginxMgr    *proxy.NginxManager
	sslMgr      *proxy.SSLManager
	adminFS     fs.FS
	userFS      fs.FS
	logger      *slog.Logger
	adminServer *http.Server
	userServer  *http.Server
}

func NewDualServer(
	cfg *config.Config,
	db *storage.DB,
	prov *provisioner.Provisioner,
	nginxMgr *proxy.NginxManager,
	sslMgr *proxy.SSLManager,
	adminFS fs.FS,
	userFS fs.FS,
	logger *slog.Logger,
) *DualServer {
	if logger == nil {
		logger = slog.Default()
	}
	return &DualServer{
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

func (s *DualServer) Start(ctx context.Context) error {
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// 1. Setup Admin Router (Port 8443)
	adminRouter := chi.NewRouter()
	adminRouter.Use(middleware.RequestID)
	adminRouter.Use(middleware.RealIP)
	adminRouter.Use(middleware.Logger)
	adminRouter.Use(middleware.Recoverer)
	adminRouter.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	setupH := api.NewSetupHandler(s.db, s.cfg.Server.JWTSecret, s.cfg.Server.JWTExpiryHours)
	adminH := api.NewAdminHandler(s.cfg, s.db, s.prov, s.nginxMgr, s.sslMgr, s.cfg.Server.JWTSecret, s.cfg.Server.JWTExpiryHours)

	adminRouter.Route("/api", func(r chi.Router) {
		r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","panel":"bee-panel"}`))
		})

		r.Route("/setup", func(sr chi.Router) {
			sr.Get("/status", setupH.GetStatus)
			sr.Post("/register", setupH.RegisterInitialAdmin)
		})

		r.Post("/admin/login", adminH.Login)

		// Protected Admin Routes
		r.Group(func(pr chi.Router) {
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

			// Security (Firewall & Fail2ban)
			pr.Get("/admin/security/firewall/status", adminH.GetFirewallStatus)
			pr.Post("/admin/security/firewall/toggle", adminH.ToggleFirewall)
			pr.Post("/admin/security/firewall/rules", adminH.AddFirewallRule)
			pr.Delete("/admin/security/firewall/rules/{number}", adminH.DeleteFirewallRule)
			pr.Get("/admin/security/fail2ban/status", adminH.GetFail2banStatus)
			pr.Post("/admin/security/fail2ban/ban", adminH.BanFail2banIP)
			pr.Post("/admin/security/fail2ban/unban", adminH.UnbanFail2banIP)

			// Settings, Telegram & SSH
			pr.Get("/admin/settings", adminH.GetSettings)
			pr.Put("/admin/settings", adminH.UpdateSettings)
			pr.Post("/admin/settings/telegram/test", adminH.SendTelegramTest)
			pr.Get("/admin/settings/ssh/port", adminH.GetSSHPort)
			pr.Put("/admin/settings/ssh/port", adminH.ChangeSSHPort)
			pr.Put("/admin/settings/admin/profile", adminH.UpdateAdminProfile)
			pr.Put("/admin/settings/admin/password", adminH.UpdateAdminPassword)
		})
	})

	if s.adminFS != nil {
		s.setupSPA(adminRouter, s.adminFS)
	}

	// 2. Setup User Router (Port 3000)
	userRouter := chi.NewRouter()
	userRouter.Use(middleware.RequestID)
	userRouter.Use(middleware.RealIP)
	userRouter.Use(middleware.Logger)
	userRouter.Use(middleware.Recoverer)
	userRouter.Use(cors.Handler(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Accept", "Authorization", "Content-Type"},
	}))

	userH := api.NewUserHandler(s.db, s.nginxMgr, s.sslMgr)

	userRouter.Route("/api", func(r chi.Router) {
		r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","portal":"user-portal"}`))
		})
		r.Get("/user/domains", userH.ListDomains)
		r.Post("/user/domains", userH.BindDomain)
		r.Delete("/user/domains/{domain}", userH.DeleteDomain)
		r.Get("/user/domains/{domain}/logs", userH.GetDomainLogs)
		r.Post("/user/domains/{domain}/renew-ssl", userH.RenewSSL)
	})

	if s.userFS != nil {
		s.setupSPA(userRouter, s.userFS)
	}

	// 3. Dual Listeners
	s.adminServer = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", s.cfg.Server.Host, s.cfg.Server.AdminPort),
		Handler:      adminRouter,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	s.userServer = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", s.cfg.Server.Host, s.cfg.Server.UserPort),
		Handler:      userRouter,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	g, gCtx := errgroup.WithContext(ctx)

	// Run Admin Server
	g.Go(func() error {
		s.logger.Info("Starting Admin Console Server", "addr", s.adminServer.Addr)
		if err := s.adminServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("admin server error: %w", err)
		}
		return nil
	})

	// Run User Server
	g.Go(func() error {
		s.logger.Info("Starting Developer User Portal Server", "addr", s.userServer.Addr)
		if err := s.userServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("user server error: %w", err)
		}
		return nil
	})

	// Graceful Shutdown Handler
	g.Go(func() error {
		<-gCtx.Done()
		s.logger.Info("Received termination signal. Shutting down servers gracefully...")

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()

		var sg errgroup.Group
		sg.Go(func() error { return s.adminServer.Shutdown(shutdownCtx) })
		sg.Go(func() error { return s.userServer.Shutdown(shutdownCtx) })
		return sg.Wait()
	})

	return g.Wait()
}

func (s *DualServer) setupSPA(r *chi.Mux, staticFS fs.FS) {
	fileServer := http.FileServer(http.FS(staticFS))

	r.Handle("/*", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		path := strings.TrimPrefix(req.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}

		if _, err := fs.Stat(staticFS, path); err != nil {
			// Fallback to index.html for SPA client-side routes
			req.URL.Path = "/"
		}
		fileServer.ServeHTTP(w, req)
	}))
}
