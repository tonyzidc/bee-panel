package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"bee-panel/internal/config"
	"bee-panel/internal/core/provisioner"
	"bee-panel/internal/core/proxy"
	"bee-panel/internal/core/security"
	"bee-panel/internal/core/system"
	"bee-panel/internal/core/updater"
	"bee-panel/internal/server"
	"bee-panel/internal/storage"
	"bee-panel/templates"
	"bee-panel/web"
)

func main() {
	configPath := flag.String("config", "", "Path to configuration file")
	flag.Parse()

	args := flag.Args()

	// If CLI command is provided
	if len(args) > 0 {
		handleCLI(args, *configPath)
		return
	}

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

	// Run Control Plane Daemon (Unified Single Port)
	logger.Info("Starting Bee Panel Control Plane Daemon...",
		"port", cfg.Server.AdminPort,
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

func handleCLI(args []string, configPath string) {
	cmd := args[0]
	switch cmd {
	case "version":
		fmt.Printf("🐝 Bee Panel %s (%s/%s, %s)\n", updater.CurrentVersion, runtime.GOOS, runtime.GOARCH, runtime.Version())
		fmt.Println("Multi-Tenant Rootless Server Provisioner & Dynamic Reverse Proxy Engine")

	case "status":
		handleStatusCLI(configPath)

	case "start":
		runSystemctl("start", "bee-panel")

	case "stop":
		runSystemctl("stop", "bee-panel")

	case "restart":
		runSystemctl("restart", "bee-panel")

	case "logs":
		handleLogsCLI(args)

	case "update":
		handleUpdateCLI(args)

	case "admin":
		handleAdminCLI(args, configPath)

	case "tenant":
		handleTenantCLI(args, configPath)

	case "firewall":
		handleFirewallCLI(args)

	case "help", "--help", "-h":
		printUsage()

	default:
		fmt.Printf("Unknown command: %s\nRun 'bee-panel help' for usage.\n", cmd)
		os.Exit(1)
	}
}

func handleStatusCLI(configPath string) {
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		fmt.Printf("⚠️ Warning: Could not load config: %v\n", err)
	}

	// Service status
	out, _ := exec.Command("systemctl", "is-active", "bee-panel").CombinedOutput()
	srvState := strings.TrimSpace(string(out))
	if srvState == "" {
		srvState = "inactive / not installed as service"
	}

	fmt.Println("==========================================================")
	fmt.Println("🐝 Bee Panel Control Plane Status")
	fmt.Println("==========================================================")
	fmt.Printf("Service Status:      %s\n", srvState)
	if cfg != nil {
		fmt.Printf("Panel Port:          :%d (Admin Console & Developer Portal /portal)\n", cfg.Server.AdminPort)
		fmt.Printf("Database Path:       %s\n", cfg.Storage.DBPath)
	}

	// Check DB
	if cfg != nil {
		db, err := storage.OpenDB(cfg.Storage.DBPath)
		if err == nil {
			tenants, _ := db.ListTenants()
			domains, _ := db.ListDomainMappings(0)
			fmt.Printf("Active Tenants:      %d\n", len(tenants))
			fmt.Printf("Configured Domains:  %d\n", len(domains))
			db.Close()
		}
	}
	fmt.Println("==========================================================")
}

func runSystemctl(action, service string) {
	cmd := exec.Command("systemctl", action, service)
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("❌ Failed to %s %s: %s (%v)\n", action, service, string(out), err)
		os.Exit(1)
	}
	fmt.Printf("✅ %s %s completed successfully.\n", action, service)
}

func handleLogsCLI(args []string) {
	cmdArgs := []string{"-u", "bee-panel", "-n", "100"}
	for _, a := range args[1:] {
		if a == "-f" || a == "--follow" {
			cmdArgs = append(cmdArgs, "-f")
		}
	}
	cmd := exec.Command("journalctl", cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
}

func handleUpdateCLI(args []string) {
	u := updater.NewUpdater()
	if len(args) > 1 && (args[1] == "--check" || args[1] == "check") {
		fmt.Println("🔍 Checking for updates from GitHub...")
		info, err := u.CheckUpdate()
		if err != nil {
			fmt.Printf("❌ Update check failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Current Version: %s\nLatest Version:  %s\n", info.CurrentVersion, info.LatestVersion)
		if info.HasUpdate {
			fmt.Println("🎉 A new update is available! Run 'bee-panel update' to apply.")
		} else {
			fmt.Println("✅ You are running the latest version.")
		}
		return
	}

	fmt.Println("⬇️ Starting Bee Panel self-update...")
	if err := u.PerformSelfUpdate(); err != nil {
		fmt.Printf("❌ Self-update failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✅ Update applied successfully! Daemon has been reloaded.")
}

func handleAdminCLI(args []string, configPath string) {
	if len(args) < 2 {
		fmt.Println("Usage: bee-panel admin [reset-password <username>]")
		os.Exit(1)
	}

	action := args[1]
	switch action {
	case "reset-password":
		username := "admin"
		if len(args) >= 3 {
			username = args[2]
		}

		cfg, err := config.LoadConfig(configPath)
		if err != nil {
			fmt.Printf("❌ Load config failed: %v\n", err)
			os.Exit(1)
		}

		db, err := storage.OpenDB(cfg.Storage.DBPath)
		if err != nil {
			fmt.Printf("❌ Open DB failed: %v\n", err)
			os.Exit(1)
		}
		defer db.Close()

		newPassword, _ := system.GenerateRandomPassword(16)
		if err := db.ResetAdminPasswordByUsername(username, newPassword); err != nil {
			fmt.Printf("❌ Password reset failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("==========================================================")
		fmt.Printf("✅ Admin password reset for user '%s'!\n", username)
		fmt.Printf("New Password: %s\n", newPassword)
		fmt.Println("Please log in and change your password in Settings.")
		fmt.Println("==========================================================")

	default:
		fmt.Printf("Unknown admin action: %s\n", action)
		os.Exit(1)
	}
}

func handleTenantCLI(args []string, configPath string) {
	if len(args) < 2 {
		fmt.Println("Usage: bee-panel tenant [list|create|delete|info|restart] <username>")
		os.Exit(1)
	}

	action := args[1]
	logger := slog.Default()
	prov := provisioner.NewProvisioner(logger)

	cfg, _ := config.LoadConfig(configPath)
	var db *storage.DB
	if cfg != nil {
		db, _ = storage.OpenDB(cfg.Storage.DBPath)
		if db != nil {
			defer db.Close()
		}
	}

	switch action {
	case "list":
		if db == nil {
			fmt.Println("❌ Database unreachable")
			os.Exit(1)
		}
		tenants, err := db.ListTenants()
		if err != nil {
			fmt.Printf("❌ Failed to list tenants: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("------------------------------------------------------------------------------------------------------------------------")
		fmt.Printf("%-18s %-10s %-12s %-45s %-10s\n", "USERNAME", "UID/GID", "STATUS", "DOCKER SOCKET", "CREATED")
		fmt.Println("------------------------------------------------------------------------------------------------------------------------")
		for _, t := range tenants {
			fmt.Printf("%-18s %-10s %-12s %-45s %-10s\n",
				t.Username,
				fmt.Sprintf("%d/%d", t.UID, t.GID),
				t.Status,
				t.DockerSocket,
				t.CreatedAt.Format("2006-01-02"),
			)
		}
		fmt.Println("------------------------------------------------------------------------------------------------------------------------")

	case "create":
		if len(args) < 3 {
			fmt.Println("Usage: bee-panel tenant create <username>")
			os.Exit(1)
		}
		username := args[2]
		creds, err := prov.ProvisionTenant(username)
		if err != nil {
			fmt.Printf("❌ Tenant creation failed: %v\n", err)
			os.Exit(1)
		}

		if db != nil {
			_, _ = db.CreateTenantWithCredentials(
				creds.Username, creds.UID, creds.GID, creds.HomeDir, creds.DockerSocket,
				creds.Password, creds.PrivateKeyOpenSSH, creds.PublicKeyOpenSSH,
			)
		}

		fmt.Println("==========================================================")
		fmt.Printf("🎉 Tenant '%s' (UID %d) provisioned successfully!\n", creds.Username, creds.UID)
		fmt.Printf("Password:      %s\n", creds.Password)
		fmt.Printf("Docker Socket: %s\n", creds.DockerSocket)
		fmt.Println("----------------------------------------------------------")
		fmt.Println("Ed25519 Private Key:")
		fmt.Println(creds.PrivateKeyOpenSSH)
		fmt.Println("==========================================================")

	case "delete":
		if len(args) < 3 {
			fmt.Println("Usage: bee-panel tenant delete <username>")
			os.Exit(1)
		}
		username := args[2]
		uid := 0
		if db != nil {
			t, _ := db.GetTenant(username)
			if t != nil {
				uid = t.UID
			}
		}
		if err := prov.DeprovisionTenant(username, uid); err != nil {
			fmt.Printf("❌ Tenant deletion failed: %v\n", err)
			os.Exit(1)
		}
		if db != nil {
			_ = db.DeleteTenant(username)
		}
		fmt.Printf("✅ Tenant '%s' dismantled and cleaned up successfully.\n", username)

	case "info":
		if len(args) < 3 {
			fmt.Println("Usage: bee-panel tenant info <username>")
			os.Exit(1)
		}
		username := args[2]
		if db == nil {
			fmt.Println("❌ Database unreachable")
			os.Exit(1)
		}
		t, err := db.GetTenant(username)
		if err != nil {
			fmt.Printf("❌ Tenant '%s' not found.\n", username)
			os.Exit(1)
		}
		fmt.Println("==========================================================")
		fmt.Printf("Tenant Details: %s\n", t.Username)
		fmt.Println("==========================================================")
		fmt.Printf("UID / GID:      %d / %d\n", t.UID, t.GID)
		fmt.Printf("Status:         %s\n", t.Status)
		fmt.Printf("Home Directory: %s\n", t.HomeDir)
		fmt.Printf("Docker Socket:  %s\n", t.DockerSocket)
		if t.PasswordPlain != "" {
			fmt.Printf("Password:       %s\n", t.PasswordPlain)
		}
		if t.PublicKey != "" {
			fmt.Println("Public Key:")
			fmt.Println(t.PublicKey)
		}
		fmt.Println("==========================================================")

	case "restart":
		if len(args) < 3 {
			fmt.Println("Usage: bee-panel tenant restart <username>")
			os.Exit(1)
		}
		username := args[2]
		uid := 0
		if db != nil {
			t, _ := db.GetTenant(username)
			if t != nil {
				uid = t.UID
			}
		}
		if err := prov.RestartTenantDocker(username, uid); err != nil {
			fmt.Printf("❌ Failed to restart tenant docker: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ Tenant '%s' rootless docker daemon restarted.\n", username)

	default:
		fmt.Printf("Unknown tenant action: %s\n", action)
		os.Exit(1)
	}
}

func handleFirewallCLI(args []string) {
	fw := security.NewFirewallManager()
	if len(args) < 2 {
		fmt.Println("Usage: bee-panel firewall [status|allow <port>|deny <port>]")
		os.Exit(1)
	}
	action := args[1]
	switch action {
	case "status":
		status, err := fw.Status()
		if err != nil {
			fmt.Printf("❌ Firewall error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Firewall Enabled: %v\n", status.Enabled)
		fmt.Println("Rules:")
		for _, r := range status.Rules {
			fmt.Printf("[%2d] %-25s %-10s %-20s %s\n", r.Number, r.To, r.Action, r.From, r.Comment)
		}
	case "allow":
		if len(args) < 3 {
			fmt.Println("Usage: bee-panel firewall allow <port>[/tcp|udp]")
			os.Exit(1)
		}
		if err := fw.AddRule(args[2], "any", "allow", "Anywhere", "CLI rule"); err != nil {
			fmt.Printf("❌ Failed to allow port: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ Allowed port %s in firewall.\n", args[2])
	case "deny":
		if len(args) < 3 {
			fmt.Println("Usage: bee-panel firewall deny <port>[/tcp|udp]")
			os.Exit(1)
		}
		if err := fw.AddRule(args[2], "any", "deny", "Anywhere", "CLI rule"); err != nil {
			fmt.Printf("❌ Failed to deny port: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ Denied port %s in firewall.\n", args[2])
	default:
		fmt.Printf("Unknown firewall action: %s\n", action)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`🐝 Bee Panel - Multi-Tenant Rootless Server Provisioner

Usage:
  bee-panel [command]

Available Commands:
  version                        Print version and build architecture
  status                         Show daemon service and storage status
  start                          Start bee-panel daemon service via systemd
  stop                           Stop bee-panel daemon service via systemd
  restart                        Restart bee-panel daemon service via systemd
  logs [-f]                      Stream daemon journalctl logs
  update [--check]               Check or perform self-update from GitHub
  admin reset-password [user]    Reset admin password directly in database
  tenant list                    List all provisioned tenants
  tenant create <username>       Provision a new rootless tenant
  tenant delete <username>       Cleanly dismantle a tenant and all data
  tenant info <username>         Show tenant credentials and docker socket
  tenant restart <username>      Restart tenant rootless docker daemon
  firewall status|allow|deny     Quick UFW firewall management
  help                           Show this help message

Options:
  -config string                 Path to bee-panel.yaml configuration file`)
}
