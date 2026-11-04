package systemd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// EnableLinger enables persistent systemd user services for a user even when logged out
func EnableLinger(username string) error {
	cmd := exec.Command("loginctl", "enable-linger", username)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("loginctl enable-linger %s failed: %s (%w)", username, string(out), err)
	}
	return nil
}

// DisableLinger disables user lingering
func DisableLinger(username string) error {
	cmd := exec.Command("loginctl", "disable-linger", username)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("loginctl disable-linger %s failed: %s (%w)", username, string(out), err)
	}
	return nil
}

// TerminateUser terminates all active sessions and user manager processes for a user
func TerminateUser(username string) error {
	cmd := exec.Command("loginctl", "terminate-user", username)
	_ = cmd.Run() // proceed regardless if user has active sessions or not
	return nil
}

// EnsureRuntimeDir ensures /run/user/<UID> exists with permission 700
func EnsureRuntimeDir(uid, gid int) (string, error) {
	runtimeDir := fmt.Sprintf("/run/user/%d", uid)
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", runtimeDir, err)
	}
	if err := os.Chown(runtimeDir, uid, gid); err != nil {
		return "", fmt.Errorf("chown %s: %w", runtimeDir, err)
	}
	return runtimeDir, nil
}

// WaitForUserSession ensures user@<UID>.service is active and its D-Bus socket is ready
func WaitForUserSession(uid int, timeout time.Duration) error {
	// First ensure user@<UID>.service is explicitly triggered to start
	serviceName := fmt.Sprintf("user@%d.service", uid)
	_ = exec.Command("systemctl", "start", serviceName).Run()

	deadline := time.Now().Add(timeout)
	busSocket := filepath.Join(fmt.Sprintf("/run/user/%d", uid), "bus")

	for time.Now().Before(deadline) {
		// Check if bus socket exists
		if _, err := os.Stat(busSocket); err == nil {
			return nil
		}
		time.Sleep(150 * time.Millisecond)
	}

	return fmt.Errorf("timeout waiting for systemd user session bus at %s", busSocket)
}
