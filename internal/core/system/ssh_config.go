package system

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"

	"bee-panel/internal/core/security"
)

type SSHConfigManager struct {
	dropInPath string
	mainPath   string
}

func NewSSHConfigManager() *SSHConfigManager {
	return &SSHConfigManager{
		dropInPath: "/etc/ssh/sshd_config.d/bee-panel.conf",
		mainPath:   "/etc/ssh/sshd_config",
	}
}

// GetCurrentSSHPort inspects sshd configuration files for the configured Port
func (m *SSHConfigManager) GetCurrentSSHPort() int {
	portRe := regexp.MustCompile(`(?i)^\s*Port\s+(\d+)`)

	// 1. Check drop-in configuration first
	if f, err := os.Open(m.dropInPath); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			matches := portRe.FindStringSubmatch(scanner.Text())
			if len(matches) >= 2 {
				p, _ := strconv.Atoi(matches[1])
				_ = f.Close()
				if p > 0 {
					return p
				}
			}
		}
		_ = f.Close()
	}

	// 2. Check main sshd_config
	if f, err := os.Open(m.mainPath); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			matches := portRe.FindStringSubmatch(scanner.Text())
			if len(matches) >= 2 {
				p, _ := strconv.Atoi(matches[1])
				_ = f.Close()
				if p > 0 {
					return p
				}
			}
		}
		_ = f.Close()
	}

	return 22 // Default OpenSSH port
}

// ChangeSSHPort safely modifies the SSH listening port, adds UFW rule, tests config, and restarts sshd
func (m *SSHConfigManager) ChangeSSHPort(newPort int, fw *security.FirewallManager) error {
	if newPort < 1 || newPort > 65535 {
		return fmt.Errorf("invalid port number: %d (must be between 1 and 65535)", newPort)
	}

	if newPort == 8443 || newPort == 3000 {
		return fmt.Errorf("port %d is reserved for Bee Panel web services", newPort)
	}

	oldPort := m.GetCurrentSSHPort()
	if oldPort == newPort {
		return nil
	}

	// 1. Proactively allow the new port in UFW before altering sshd
	if fw != nil {
		_ = fw.AddRule(strconv.Itoa(newPort), "tcp", "allow", "Anywhere", "Host SSH Port")
	}

	// 2. Write drop-in config or modify main config
	if err := os.MkdirAll(filepath.Dir(m.dropInPath), 0755); err != nil {
		return fmt.Errorf("create sshd_config.d dir: %w", err)
	}

	content := fmt.Sprintf("# Managed by Bee Panel\nPort %d\n", newPort)
	if err := os.WriteFile(m.dropInPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("write ssh drop-in config: %w", err)
	}

	// 3. Test sshd config syntax
	testCmd := exec.Command("sshd", "-t")
	if out, err := testCmd.CombinedOutput(); err != nil {
		// Revert immediately
		_ = os.Remove(m.dropInPath)
		return fmt.Errorf("sshd config syntax test failed: %s (%w)", string(out), err)
	}

	// 4. Safely reload/restart ssh daemon
	restartOut, err := exec.Command("systemctl", "reload-or-restart", "ssh").CombinedOutput()
	if err != nil {
		// Fallback to sshd service name
		restartOut2, err2 := exec.Command("systemctl", "reload-or-restart", "sshd").CombinedOutput()
		if err2 != nil {
			_ = os.Remove(m.dropInPath)
			_ = exec.Command("systemctl", "restart", "ssh").Run()
			return fmt.Errorf("failed to reload ssh daemon: %s / %s", string(restartOut), string(restartOut2))
		}
	}

	return nil
}
