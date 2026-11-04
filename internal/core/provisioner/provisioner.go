package provisioner

import (
	"fmt"
	"log/slog"
	"time"

	"bee-panel/internal/core/docker"
	"bee-panel/internal/core/system"
	"bee-panel/internal/core/systemd"
)

type TenantCredentials struct {
	Username          string `json:"username"`
	UID               int    `json:"uid"`
	GID               int    `json:"gid"`
	HomeDir           string `json:"home_dir"`
	Password          string `json:"password"`
	PrivateKeyOpenSSH string `json:"private_key_openssh"`
	PublicKeyOpenSSH  string `json:"public_key_openssh"`
	DockerSocket      string `json:"docker_socket"`
}

type Provisioner struct {
	logger *slog.Logger
}

func NewProvisioner(logger *slog.Logger) *Provisioner {
	if logger == nil {
		logger = slog.Default()
	}
	return &Provisioner{logger: logger}
}

// ProvisionTenant runs the 6-step atomic user creation pipeline with complete rollback on error
func (p *Provisioner) ProvisionTenant(username string) (*TenantCredentials, error) {
	p.logger.Info("Starting tenant provisioning pipeline", "username", username)

	// Step 0: Generate SSH Credentials & Password
	creds, err := system.GenerateEd25519Keypair(fmt.Sprintf("%s@bee-panel", username))
	if err != nil {
		return nil, fmt.Errorf("generate credentials: %w", err)
	}

	// State tracking for atomic rollback
	var userCreated bool
	var lingerEnabled bool
	var userInfo *system.UserInfo

	rollback := func(failedStep string, originalErr error) error {
		p.logger.Warn("Provisioning failed. Initiating rollback...",
			"failed_step", failedStep,
			"error", originalErr,
			"username", username,
		)

		if lingerEnabled {
			_ = systemd.DisableLinger(username)
			_ = systemd.TerminateUser(username)
		}

		if userCreated {
			_ = system.DeleteLinuxUser(username)
		}

		return fmt.Errorf("step '%s' failed: %w (rollback completed)", failedStep, originalErr)
	}

	// Step 1: Create Linux User & SubUID/SubGID
	p.logger.Info("Step 1: Creating Linux user & subuid mapping", "username", username)
	userInfo, err = system.CreateLinuxUser(username, creds.Password)
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	userCreated = true

	// Step 2: Setup SSH Keys
	p.logger.Info("Step 2: Installing Ed25519 authorized keys", "username", username)
	if err := system.SetupUserSSHKeys(userInfo.HomeDir, userInfo.UID, userInfo.GID, creds.PublicKeyOpenSSH); err != nil {
		return nil, rollback("setup_ssh_keys", err)
	}

	// Step 3: Session Persistence (Systemd Linger)
	p.logger.Info("Step 3: Enabling systemd linger", "username", username)
	if err := systemd.EnableLinger(username); err != nil {
		return nil, rollback("enable_linger", err)
	}
	lingerEnabled = true

	if _, err := systemd.EnsureRuntimeDir(userInfo.UID, userInfo.GID); err != nil {
		return nil, rollback("ensure_runtime_dir", err)
	}

	// Wait for systemd user session & D-Bus bus to become active
	if err := systemd.WaitForUserSession(userInfo.UID, 10*time.Second); err != nil {
		return nil, rollback("wait_for_user_session", err)
	}

	// Step 4: Setup Rootless Docker
	p.logger.Info("Step 4: Setting up rootless docker with pasta driver", "username", username)
	dockerCfg := &docker.RootlessDockerConfig{
		Username: username,
		UID:      userInfo.UID,
		GID:      userInfo.GID,
		HomeDir:  userInfo.HomeDir,
	}
	if err := docker.SetupRootlessDocker(dockerCfg); err != nil {
		_ = docker.StopRootlessDocker(username, userInfo.UID)
		return nil, rollback("setup_rootless_docker", err)
	}

	socketPath := fmt.Sprintf("/run/user/%d/docker.sock", userInfo.UID)
	p.logger.Info("Tenant provisioning completed successfully",
		"username", username,
		"uid", userInfo.UID,
		"docker_socket", socketPath,
	)

	return &TenantCredentials{
		Username:          username,
		UID:               userInfo.UID,
		GID:               userInfo.GID,
		HomeDir:           userInfo.HomeDir,
		Password:          creds.Password,
		PrivateKeyOpenSSH: creds.PrivateKeyOpenSSH,
		PublicKeyOpenSSH:  creds.PublicKeyOpenSSH,
		DockerSocket:      socketPath,
	}, nil
}

// DeprovisionTenant cleanly dismantles a tenant: stops docker, kills user sessions, deletes user and data
func (p *Provisioner) DeprovisionTenant(username string, uid int) error {
	p.logger.Info("Deprovisioning tenant...", "username", username, "uid", uid)

	// 1. Stop rootless docker
	_ = docker.StopRootlessDocker(username, uid)

	// 2. Terminate user sessions and disable linger
	_ = systemd.DisableLinger(username)
	_ = systemd.TerminateUser(username)

	// 3. Delete user & subuid/subgid
	if err := system.DeleteLinuxUser(username); err != nil {
		return fmt.Errorf("delete user: %w", err)
	}

	p.logger.Info("Tenant deprovisioned successfully", "username", username)
	return nil
}
