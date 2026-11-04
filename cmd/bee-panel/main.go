package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"bee-panel/internal/config"
	"bee-panel/internal/core/provisioner"
	"bee-panel/internal/core/proxy"
	"bee-panel/internal/server"
	"bee-panel/internal/storage"
	"bee-panel/templates"
	"bee-panel/web"
)

func main() {
	configPath := flag.String("config", "", "Path to configuration file")
	flag.Parse()

	// Structured JSON Logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		logger.Error("Failed to load config", "error", err)
		os.Exit(1)
	}

	args := flag.Args()

	// If CLI command is provided (e.g. tenant create / delete)
	if len(args) > 0 {
		switch args[0] {
		case "tenant":
			handleTenantCLI(args, logger)
			return
		case "version":
			fmt.Println("Bee Panel v0.1.0-alpha (Rootless Multi-Tenant Provisioner)")
			return
		}
	}

	// Default: Run Control Plane Daemon (Dual HTTP Servers)
	logger.Info("Starting Bee Panel Control Plane Daemon...",
		"admin_port", cfg.Server.AdminPort,
		"user_port", cfg.Server.UserPort,
		"db_path", cfg.Storage.DBPath,
	)

	// 1. Open SQLite Storage
	db, err := storage.OpenDB(cfg.Storage.DBPath)
	if err != nil {
		logger.Error("Failed to open SQLite database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	// 2. Initialize Core Provisioner & Proxy Engines
	prov := provisioner.NewProvisioner(logger)
	nginxMgr := proxy.NewNginxManager(
		cfg.Proxy.NginxConfDir,
		cfg.Proxy.NginxEnabledDir,
		cfg.Proxy.AcmeWebroot,
		templates.NginxVHostTemplate,
	)
	sslMgr := proxy.NewSSLManager(cfg.Proxy.AcmeWebroot, "admin@bee-panel.local", logger)

	// 3. Start Background SSL Auto-Renew Worker
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sslMgr.StartAutoRenewWorker(ctx, 0) // default 12h

	// 4. Initialize and Run Dual HTTP Server
	adminFS := web.AdminFS()
	userFS := web.UserFS()

	dualSrv := server.NewDualServer(
		cfg,
		db,
		prov,
		nginxMgr,
		sslMgr,
		adminFS,
		userFS,
		logger,
	)

	if err := dualSrv.Start(ctx); err != nil {
		logger.Error("Server shutdown with error", "error", err)
		os.Exit(1)
	}

	logger.Info("Bee Panel stopped cleanly.")
}

func handleTenantCLI(args []string, logger *slog.Logger) {
	if len(args) < 3 {
		fmt.Println("Usage: bee-panel tenant [create|delete] <username>")
		os.Exit(1)
	}
	action := args[1]
	username := args[2]

	prov := provisioner.NewProvisioner(logger)

	switch action {
	case "create":
		creds, err := prov.ProvisionTenant(username)
		if err != nil {
			logger.Error("Tenant creation failed", "error", err)
			os.Exit(1)
		}
		fmt.Println("==========================================================")
		fmt.Printf("🎉 Tenant '%s' (UID %d) provisioned successfully!\n", creds.Username, creds.UID)
		fmt.Printf("Password: %s\n", creds.Password)
		fmt.Printf("Docker Socket: %s\n", creds.DockerSocket)
		fmt.Println("----------------------------------------------------------")
		fmt.Println("Ed25519 Private Key:")
		fmt.Println(creds.PrivateKeyOpenSSH)
		fmt.Println("==========================================================")

	case "delete":
		if err := prov.DeprovisionTenant(username, 0); err != nil {
			logger.Error("Tenant deletion failed", "error", err)
			os.Exit(1)
		}
		fmt.Printf("✅ Tenant '%s' dismantled and cleaned up successfully.\n", username)

	default:
		fmt.Printf("Unknown tenant action: %s\n", action)
		os.Exit(1)
	}
}
