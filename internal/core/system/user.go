package system

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultSubUIDCount = 65536
	BaseSubUID         = 100000
)

type UserInfo struct {
	Username    string
	UID         int
	GID         int
	HomeDir     string
	SubUIDStart int
	SubUIDCount int
}

// UserExists checks if a system user exists
func UserExists(username string) bool {
	cmd := exec.Command("id", "-u", username)
	return cmd.Run() == nil
}

// GetNextAvailableSubUID finds the next free SubUID range
func GetNextAvailableSubUID() (int, error) {
	file, err := os.Open("/etc/subuid")
	if err != nil {
		if os.IsNotExist(err) {
			return BaseSubUID, nil
		}
		return 0, fmt.Errorf("open /etc/subuid: %w", err)
	}
	defer file.Close()

	maxEnd := BaseSubUID
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) >= 3 {
			start, err1 := strconv.Atoi(parts[1])
			count, err2 := strconv.Atoi(parts[2])
			if err1 == nil && err2 == nil {
				if start+count > maxEnd {
					maxEnd = start + count
				}
			}
		}
	}

	return maxEnd, nil
}

// CreateLinuxUser creates a new system user with /bin/bash, assigns subuid/subgid range and sets home perm to 700
func CreateLinuxUser(username string, password string) (*UserInfo, error) {
	if UserExists(username) {
		return nil, fmt.Errorf("user %s already exists", username)
	}

	// 1. useradd -m -s /bin/bash <username>
	cmd := exec.Command("useradd", "-m", "-s", "/bin/bash", username)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("useradd failed: %s (%w)", string(out), err)
	}

	// 2. Set password if provided
	if password != "" {
		chpasswdCmd := exec.Command("chpasswd")
		chpasswdCmd.Stdin = strings.NewReader(fmt.Sprintf("%s:%s", username, password))
		if out, err := chpasswdCmd.CombinedOutput(); err != nil {
			// Rollback user
			_ = exec.Command("userdel", "-r", username).Run()
			return nil, fmt.Errorf("set password failed: %s (%w)", string(out), err)
		}
	}

	// 3. Retrieve UID and GID
	idCmd := exec.Command("id", "-u", username)
	uidBytes, err := idCmd.Output()
	if err != nil {
		_ = exec.Command("userdel", "-r", username).Run()
		return nil, fmt.Errorf("get uid failed: %w", err)
	}
	uid, _ := strconv.Atoi(strings.TrimSpace(string(uidBytes)))

	gidCmd := exec.Command("id", "-g", username)
	gidBytes, err := gidCmd.Output()
	if err != nil {
		_ = exec.Command("userdel", "-r", username).Run()
		return nil, fmt.Errorf("get gid failed: %w", err)
	}
	gid, _ := strconv.Atoi(strings.TrimSpace(string(gidBytes)))

	homeDir := fmt.Sprintf("/home/%s", username)

	// 4. Secure home permissions (700)
	if err := os.Chmod(homeDir, 0700); err != nil {
		_ = exec.Command("userdel", "-r", username).Run()
		return nil, fmt.Errorf("chmod home dir failed: %w", err)
	}

	// 5. Ensure SubUID/SubGID are allocated
	subUIDStart, err := ensureSubUIDRange(username)
	if err != nil {
		_ = exec.Command("userdel", "-r", username).Run()
		return nil, fmt.Errorf("subuid allocation failed: %w", err)
	}

	return &UserInfo{
		Username:    username,
		UID:         uid,
		GID:         gid,
		HomeDir:     homeDir,
		SubUIDStart: subUIDStart,
		SubUIDCount: DefaultSubUIDCount,
	}, nil
}

// ensureSubUIDRange checks and appends subuid & subgid mapping if not present
func ensureSubUIDRange(username string) (int, error) {
	// Check if already mapped
	subuidContent, _ := os.ReadFile("/etc/subuid")
	if strings.Contains(string(subuidContent), username+":") {
		// Existing mapping, parse start
		lines := strings.Split(string(subuidContent), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, username+":") {
				parts := strings.Split(line, ":")
				if len(parts) >= 2 {
					start, _ := strconv.Atoi(parts[1])
					return start, nil
				}
			}
		}
	}

	start, err := GetNextAvailableSubUID()
	if err != nil {
		return 0, err
	}

	mapping := fmt.Sprintf("%s:%d:%d\n", username, start, DefaultSubUIDCount)

	// Append to /etc/subuid
	f1, err := os.OpenFile("/etc/subuid", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return 0, fmt.Errorf("open /etc/subuid for append: %w", err)
	}
	defer f1.Close()
	if _, err := f1.WriteString(mapping); err != nil {
		return 0, fmt.Errorf("write /etc/subuid: %w", err)
	}

	// Append to /etc/subgid
	f2, err := os.OpenFile("/etc/subgid", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return 0, fmt.Errorf("open /etc/subgid for append: %w", err)
	}
	defer f2.Close()
	if _, err := f2.WriteString(mapping); err != nil {
		return 0, fmt.Errorf("write /etc/subgid: %w", err)
	}

	return start, nil
}

// DeleteLinuxUser completely cleans up the user, processes, home directory and subuid/subgid
func DeleteLinuxUser(username string) error {
	// 1. Retry loop to kill all processes owned by the user
	for i := 0; i < 5; i++ {
		_ = exec.Command("pkill", "-9", "-u", username).Run()
		time.Sleep(200 * time.Millisecond)
		// Check if any process remains
		cmd := exec.Command("pgrep", "-u", username)
		if err := cmd.Run(); err != nil {
			// No processes left
			break
		}
	}

	// 2. userdel -f -r <username> (force remove user and home dir)
	cmd := exec.Command("userdel", "-f", "-r", username)
	if out, err := cmd.CombinedOutput(); err != nil {
		// If user was already deleted, don't fail
		if UserExists(username) {
			return fmt.Errorf("userdel failed: %s (%w)", string(out), err)
		}
	}

	// 3. Cleanup /etc/subuid & /etc/subgid
	removeSubMapping("/etc/subuid", username)
	removeSubMapping("/etc/subgid", username)

	return nil
}

func removeSubMapping(filePath, username string) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return
	}
	lines := strings.Split(string(content), "\n")
	var newLines []string
	prefix := username + ":"
	for _, l := range lines {
		if !strings.HasPrefix(l, prefix) && strings.TrimSpace(l) != "" {
			newLines = append(newLines, l)
		}
	}
	_ = os.WriteFile(filePath, []byte(strings.Join(newLines, "\n")+"\n"), 0644)
}
