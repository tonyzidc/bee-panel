package docker

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type RootlessDockerConfig struct {
	Username string
	UID      int
	GID      int
	HomeDir  string
}

// SetupRootlessDocker initializes and starts rootless Docker for the given tenant user
func SetupRootlessDocker(cfg *RootlessDockerConfig) error {
	// 1. Create ~/.config/docker with log-limiting daemon.json (avoids disk exhaustion)
	dockerConfigDir := filepath.Join(cfg.HomeDir, ".config", "docker")
	if err := os.MkdirAll(dockerConfigDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dockerConfigDir, err)
	}
	daemonJSON := "{\n  \"log-driver\": \"json-file\",\n  \"log-opts\": {\n    \"max-size\": \"10m\",\n    \"max-file\": \"3\"\n  }\n}\n"
	if err := os.WriteFile(filepath.Join(dockerConfigDir, "daemon.json"), []byte(daemonJSON), 0644); err != nil {
		return fmt.Errorf("write daemon.json: %w", err)
	}

	// 2. Configure systemd user drop-in to enforce pasta network driver
	systemdOverrideDir := filepath.Join(cfg.HomeDir, ".config", "systemd", "user", "docker.service.d")
	if err := os.MkdirAll(systemdOverrideDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", systemdOverrideDir, err)
	}
	overrideConf := "[Service]\nEnvironment=\"DOCKERD_ROOTLESS_ROOTLESSKIT_NET=pasta\"\nEnvironment=\"DOCKERD_ROOTLESS_ROOTLESSKIT_PORT_DRIVER=implicit\"\n"
	if err := os.WriteFile(filepath.Join(systemdOverrideDir, "override.conf"), []byte(overrideConf), 0644); err != nil {
		return fmt.Errorf("write override.conf: %w", err)
	}

	// Fix ownership of entire ~/.config tree
	_ = exec.Command("chown", "-R", fmt.Sprintf("%d:%d", cfg.UID, cfg.GID), filepath.Join(cfg.HomeDir, ".config")).Run()

	// 3. Ensure runtime dir is prepared
	runtimeDir := fmt.Sprintf("/run/user/%d", cfg.UID)
	_ = os.MkdirAll(runtimeDir, 0700)
	_ = os.Chown(runtimeDir, cfg.UID, cfg.GID)

	// 4. Run dockerd-rootless-setuptool.sh install under user
	installCmd := fmt.Sprintf(
		"export XDG_RUNTIME_DIR=%s; export DBUS_SESSION_BUS_ADDRESS=unix:path=%s/bus; dockerd-rootless-setuptool.sh install",
		runtimeDir, runtimeDir,
	)
	cmd := exec.Command("su", "-", cfg.Username, "-c", installCmd)
	out, err := cmd.CombinedOutput()
	fmt.Printf("[dockerd-rootless-setuptool output]:\n%s\n", string(out))
	if err != nil {
		return fmt.Errorf("dockerd-rootless install failed: %s (%w)", string(out), err)
	}

	// 5. Append environment variables to ~/.bashrc
	bashrcPath := filepath.Join(cfg.HomeDir, ".bashrc")
	envBlock := `
# Bee Panel Rootless Docker Environment
export XDG_RUNTIME_DIR="/run/user/$(id -u)"
export DOCKER_HOST="unix:///run/user/$(id -u)/docker.sock"
`
	f, err := os.OpenFile(bashrcPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		_, _ = f.WriteString(envBlock)
		_ = f.Close()
		_ = os.Chown(bashrcPath, cfg.UID, cfg.GID)
	}

	// 6. Verify docker socket is healthy
	socketPath := filepath.Join(runtimeDir, "docker.sock")
	if err := WaitForSocket(socketPath, 15*time.Second); err != nil {
		return fmt.Errorf("docker socket failed healthcheck: %w", err)
	}

	return nil
}

// StopRootlessDocker cleanly stops rootless docker for a user
func StopRootlessDocker(username string, uid int) error {
	runtimeDir := fmt.Sprintf("/run/user/%d", uid)
	stopCmd := fmt.Sprintf(
		"export XDG_RUNTIME_DIR=%s; systemctl --user stop docker 2>/dev/null || true",
		runtimeDir,
	)
	_ = exec.Command("su", "-", username, "-c", stopCmd).Run()
	return nil
}

// WaitForSocket polls a unix socket until responsive or timeout
func WaitForSocket(socketPath string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			// Try connecting via HTTP client over unix socket
			client := http.Client{
				Transport: &http.Transport{
					DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
						return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
					},
				},
				Timeout: 2 * time.Second,
			}
			resp, err := client.Get("http://localhost/_ping")
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return nil
				}
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for docker socket at %s", socketPath)
}
