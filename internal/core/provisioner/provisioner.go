package provisioner

import (
	"fmt"
	"log/slog"
	"os/exec"
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
	PrivateKey        string `json:"private_key"`
	PrivateKeyOpenSSH string `json:"private_key_openssh"`
	PublicKey         string `json:"public_key"`
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

// ProvisionTenant runs the atomic user creation pipeline with complete rollback on error
func (p *Provisioner) ProvisionTenant(username string) (*TenantCredentials, error) {
	return p.ProvisionTenantWithCustom(username, "", "")
}

// ProvisionTenantWithCustom allows specifying initial password or custom public key
func (p *Provisioner) ProvisionTenantWithCustom(username, customPassword, customPubKey string) (*TenantCredentials, error) {
	p.logger.Info("Starting tenant provisioning pipeline", "username", username)

	var privKey, pubKey, password string
	if customPubKey != "" {
		pubKey = customPubKey
	} else {
		creds, err := system.GenerateEd25519Keypair(fmt.Sprintf("%s@bee-panel", username))
		if err != nil {
			return nil, fmt.Errorf("generate credentials: %w", err)
		}
		privKey = creds.PrivateKeyOpenSSH
		pubKey = creds.PublicKeyOpenSSH
	}

	if customPassword != "" {
		password = customPassword
	} else {
		pwd, err := system.GenerateRandomPassword(24)
		if err != nil {
			return nil, fmt.Errorf("generate password: %w", err)
		}
		password = pwd
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
	var err error
	userInfo, err = system.CreateLinuxUser(username, password)
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	userCreated = true

	// Step 2: Setup SSH Keys
	p.logger.Info("Step 2: Installing Ed25519 authorized keys", "username", username)
	if err := system.SetupUserSSHKeys(userInfo.HomeDir, userInfo.UID, userInfo.GID, pubKey); err != nil {
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
		Password:          password,
		PrivateKey:        privKey,
		PrivateKeyOpenSSH: privKey,
		PublicKey:         pubKey,
		PublicKeyOpenSSH:  pubKey,
		DockerSocket:      socketPath,
	}, nil
}

// SuspendTenant stops tenant docker and locks Linux account
func (p *Provisioner) SuspendTenant(username string, uid int) error {
	_ = docker.StopRootlessDocker(username, uid)
	_ = systemd.DisableLinger(username)
	_ = systemd.TerminateUser(username)
	return system.LockLinuxUser(username)
}

// ResumeTenant unlocks Linux account and enables systemd linger/docker
func (p *Provisioner) ResumeTenant(username string, uid int) error {
	if err := system.UnlockLinuxUser(username); err != nil {
		return err
	}
	_ = systemd.EnableLinger(username)
	runtimeDir := fmt.Sprintf("/run/user/%d", uid)
	startCmd := fmt.Sprintf("export XDG_RUNTIME_DIR=%s; systemctl --user start docker", runtimeDir)
	_ = exec.Command("su", "-", username, "-c", startCmd).Run()
	return nil
}

// RestartTenantDocker restarts the rootless docker daemon for a tenant
func (p *Provisioner) RestartTenantDocker(username string, uid int) error {
	runtimeDir := fmt.Sprintf("/run/user/%d", uid)
	restartCmd := fmt.Sprintf("export XDG_RUNTIME_DIR=%s; systemctl --user restart docker", runtimeDir)
	out, err := exec.Command("su", "-", username, "-c", restartCmd).CombinedOutput()
	if err != nil {
		return fmt.Errorf("restart docker error: %s (%w)", string(out), err)
	}
	return nil
}

// ChangePassword changes the user password
func (p *Provisioner) ChangePassword(username, newPassword string) error {
	return system.ChangeLinuxUserPassword(username, newPassword)
}

// RotateSSHKey generates a new keypair or installs custom public key
func (p *Provisioner) RotateSSHKey(username string, uid, gid int, homeDir, customPubKey string) (string, string, error) {
	var privKey, pubKey string
	if customPubKey != "" {
		pubKey = customPubKey
	} else {
		creds, err := system.GenerateEd25519Keypair(fmt.Sprintf("%s@bee-panel", username))
		if err != nil {
			return "", "", err
		}
		privKey = creds.PrivateKeyOpenSSH
		pubKey = creds.PublicKeyOpenSSH
	}

	if err := system.ReplaceUserSSHKey(homeDir, uid, gid, pubKey); err != nil {
		return "", "", err
	}

	return privKey, pubKey, nil
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
