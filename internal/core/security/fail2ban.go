package security

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type BannedIPInfo struct {
	Jail          string `json:"jail"`
	IP            string `json:"ip"`
	BanTime       string `json:"ban_time,omitempty"`
	ExpireTime    string `json:"expire_time,omitempty"`
	Failures      int    `json:"failures,omitempty"`
	AttackType    string `json:"attack_type,omitempty"`
	TriggerDetail string `json:"trigger_detail,omitempty"`
}

type Fail2banStatus struct {
	Active      bool           `json:"active"`
	Jails       []string       `json:"jails"`
	TotalBanned int            `json:"total_banned"`
	BannedList  []BannedIPInfo `json:"banned_list"`
}

type Fail2banConfig struct {
	Bantime  string `json:"bantime"`
	Findtime string `json:"findtime"`
	MaxRetry int    `json:"maxretry"`
	IgnoreIP string `json:"ignoreip"`
}

type Fail2banManager struct{}

func NewFail2banManager() *Fail2banManager {
	return &Fail2banManager{}
}

var banTimeRegex = regexp.MustCompile(`^(\S+)\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+\+\s+(\d+)\s+=\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})`)

func parseBanTimeOutput(jail, output string) []BannedIPInfo {
	var list []BannedIPInfo
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		matches := banTimeRegex.FindStringSubmatch(line)
		if len(matches) >= 5 {
			list = append(list, BannedIPInfo{
				Jail:       jail,
				IP:         matches[1],
				BanTime:    matches[2],
				ExpireTime: matches[4],
			})
		} else {
			// Fallback: split by fields if format slightly differs
			fields := strings.Fields(line)
			if len(fields) >= 1 && strings.Contains(fields[0], ".") {
				list = append(list, BannedIPInfo{
					Jail: jail,
					IP:   fields[0],
				})
			}
		}
	}
	return list
}

func readTailLogLines(path string, maxLines int) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if len(lines) > maxLines {
		return lines[len(lines)-maxLines:]
	}
	return lines
}

var (
	reInvalidUser = regexp.MustCompile(`Invalid user (\S+) from (\S+)`)
	reFailedPass  = regexp.MustCompile(`Failed password for (?:invalid user )?(\S+) from (\S+)`)
	reConnClosed  = regexp.MustCompile(`Connection closed by (?:invalid user )?(\S+)\s+(\S+)`)
)

func analyzeLogLinesForIP(ip string, authLines, f2bLines []string) (attackType string, triggerDetail string, failureCount int) {
	for _, line := range authLines {
		if !strings.Contains(line, ip) {
			continue
		}
		failureCount++
		if m := reFailedPass.FindStringSubmatch(line); len(m) >= 3 && m[2] == ip {
			attackType = fmt.Sprintf("SSH Brute Force: Password (User: %s)", m[1])
			triggerDetail = line
		} else if m := reInvalidUser.FindStringSubmatch(line); len(m) >= 3 && m[2] == ip {
			if attackType == "" {
				attackType = fmt.Sprintf("SSH Invalid User Probe (User: %s)", m[1])
			}
			triggerDetail = line
		} else if m := reConnClosed.FindStringSubmatch(line); len(m) >= 3 && m[2] == ip {
			if attackType == "" {
				attackType = fmt.Sprintf("SSH Connection Probe (%s)", m[1])
			}
			if triggerDetail == "" {
				triggerDetail = line
			}
		} else if strings.Contains(line, "authentication failure") {
			if triggerDetail == "" {
				triggerDetail = line
			}
		}
	}

	for _, line := range f2bLines {
		if !strings.Contains(line, ip) {
			continue
		}
		if strings.Contains(line, "Found "+ip) {
			failureCount++
		}
		if triggerDetail == "" && strings.Contains(line, "Ban "+ip) {
			triggerDetail = line
		}
	}

	if attackType == "" {
		attackType = "SSH Intrusion / Auth Failure"
	}
	if triggerDetail == "" {
		triggerDetail = fmt.Sprintf("Repeated failed attempts triggered jail policy for IP %s", ip)
	}
	if failureCount <= 0 {
		failureCount = 5
	}

	return attackType, triggerDetail, failureCount
}

func enrichBannedList(bannedList []BannedIPInfo) []BannedIPInfo {
	if len(bannedList) == 0 {
		return bannedList
	}

	authLines := readTailLogLines("/var/log/auth.log", 3000)
	f2bLines := readTailLogLines("/var/log/fail2ban.log", 3000)

	for i := range bannedList {
		item := &bannedList[i]
		aType, trigger, count := analyzeLogLinesForIP(item.IP, authLines, f2bLines)
		item.AttackType = aType
		item.TriggerDetail = trigger
		item.Failures = count
		if item.BanTime == "" {
			item.BanTime = "Active"
		}
		if item.ExpireTime == "" {
			item.ExpireTime = "Automatic via Fail2ban"
		}
	}
	return bannedList
}

// Status returns Fail2ban active status, list of jails, and all banned IPs with forensics
func (m *Fail2banManager) Status() (*Fail2banStatus, error) {
	status := &Fail2banStatus{
		Active:     false,
		Jails:      []string{},
		BannedList: []BannedIPInfo{},
	}

	pingOut, err := exec.Command("fail2ban-client", "ping").CombinedOutput()
	if err != nil || !strings.Contains(strings.ToLower(string(pingOut)), "pong") {
		return status, nil
	}
	status.Active = true

	// Get jail list
	out, err := exec.Command("fail2ban-client", "status").CombinedOutput()
	if err != nil {
		return status, nil
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Jail list:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				rawJails := strings.Split(parts[1], ",")
				for _, j := range rawJails {
					trimmed := strings.TrimSpace(j)
					if trimmed != "" {
						status.Jails = append(status.Jails, trimmed)
					}
				}
			}
		}
	}

	// For each jail, get currently banned IPs with time
	for _, jail := range status.Jails {
		// First try get <jail> banip --with-time
		timeOut, tErr := exec.Command("fail2ban-client", "get", jail, "banip", "--with-time").CombinedOutput()
		if tErr == nil && len(strings.TrimSpace(string(timeOut))) > 0 {
			parsed := parseBanTimeOutput(jail, string(timeOut))
			status.BannedList = append(status.BannedList, parsed...)
		} else {
			// Fallback: status <jail>
			jOut, err := exec.Command("fail2ban-client", "status", jail).CombinedOutput()
			if err != nil {
				continue
			}
			jScanner := bufio.NewScanner(strings.NewReader(string(jOut)))
			for jScanner.Scan() {
				jLine := jScanner.Text()
				if strings.Contains(jLine, "Banned IP list:") {
					parts := strings.Split(jLine, ":")
					if len(parts) >= 2 {
						ips := strings.Fields(parts[1])
						for _, ip := range ips {
							ip = strings.TrimSpace(ip)
							if ip != "" {
								status.BannedList = append(status.BannedList, BannedIPInfo{
									Jail: jail,
									IP:   ip,
								})
							}
						}
					}
				}
			}
		}
	}

	status.BannedList = enrichBannedList(status.BannedList)
	status.TotalBanned = len(status.BannedList)
	return status, nil
}

// BanIP bans an IP in the specified jail (default to "sshd" if empty)
func (m *Fail2banManager) BanIP(jail, ip string) error {
	jail = strings.TrimSpace(jail)
	if jail == "" {
		jail = "sshd"
	}
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return fmt.Errorf("ip cannot be empty")
	}

	out, err := exec.Command("fail2ban-client", "set", jail, "banip", ip).CombinedOutput()
	if err != nil {
		return fmt.Errorf("fail2ban ban failed: %s (%w)", string(out), err)
	}
	return nil
}

// UnbanIP unbans an IP from a jail or all jails
func (m *Fail2banManager) UnbanIP(jail, ip string) error {
	jail = strings.TrimSpace(jail)
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return fmt.Errorf("ip cannot be empty")
	}

	var cmd *exec.Cmd
	if jail != "" {
		cmd = exec.Command("fail2ban-client", "set", jail, "unbanip", ip)
	} else {
		cmd = exec.Command("fail2ban-client", "unban", ip)
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("fail2ban unban failed: %s (%w)", string(out), err)
	}
	return nil
}

// Restart restarts the fail2ban service
func (m *Fail2banManager) Restart() error {
	out, err := exec.Command("systemctl", "restart", "fail2ban").CombinedOutput()
	if err != nil {
		return fmt.Errorf("fail2ban restart: %s (%w)", string(out), err)
	}
	return nil
}

// GetConfig returns the Fail2ban configuration
func (m *Fail2banManager) GetConfig() (*Fail2banConfig, error) {
	cfg := &Fail2banConfig{
		Bantime:  "1h",
		Findtime: "10m",
		MaxRetry: 5,
		IgnoreIP: "127.0.0.1/8 ::1",
	}

	path := "/etc/fail2ban/jail.local"
	data, err := os.ReadFile(path)
	if err != nil {
		path = "/etc/fail2ban/jail.conf"
		data, err = os.ReadFile(path)
	}

	if err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				k := strings.ToLower(strings.TrimSpace(parts[0]))
				v := strings.TrimSpace(parts[1])
				switch k {
				case "bantime":
					cfg.Bantime = v
				case "findtime":
					cfg.Findtime = v
				case "maxretry":
					if n, err := strconv.Atoi(v); err == nil && n > 0 {
						cfg.MaxRetry = n
					}
				case "ignoreip":
					cfg.IgnoreIP = v
				}
			}
		}
	}

	return cfg, nil
}

// UpdateConfig writes Fail2ban configuration to /etc/fail2ban/jail.local and reloads
func (m *Fail2banManager) UpdateConfig(cfg *Fail2banConfig) error {
	if cfg.Bantime == "" {
		cfg.Bantime = "1h"
	}
	if cfg.Findtime == "" {
		cfg.Findtime = "10m"
	}
	if cfg.MaxRetry <= 0 {
		cfg.MaxRetry = 5
	}
	if cfg.IgnoreIP == "" {
		cfg.IgnoreIP = "127.0.0.1/8 ::1"
	}

	content := fmt.Sprintf(`[DEFAULT]
bantime = %s
findtime = %s
maxretry = %d
ignoreip = %s

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = %d
`, cfg.Bantime, cfg.Findtime, cfg.MaxRetry, cfg.IgnoreIP, cfg.MaxRetry)

	path := "/etc/fail2ban/jail.local"
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create fail2ban dir: %w", err)
	}

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("write jail.local: %w", err)
	}

	// Try fail2ban-client reload first, fallback to systemctl restart fail2ban
	if out, err := exec.Command("fail2ban-client", "reload").CombinedOutput(); err != nil {
		_ = exec.Command("systemctl", "restart", "fail2ban").Run()
		_ = out
	}

	return nil
}
