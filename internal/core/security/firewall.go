package security

import (
	"bufio"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

type FirewallRule struct {
	Number   int    `json:"number"`
	To       string `json:"to"`
	Action   string `json:"action"`
	From     string `json:"from"`
	Comment  string `json:"comment"`
	Protocol string `json:"protocol"`
}

type FirewallStatus struct {
	Enabled bool           `json:"enabled"`
	Rules   []FirewallRule `json:"rules"`
}

type FirewallManager struct{}

func NewFirewallManager() *FirewallManager {
	return &FirewallManager{}
}

// Status returns current UFW status and parsed numbered rules
func (m *FirewallManager) Status() (*FirewallStatus, error) {
	out, err := exec.Command("ufw", "status", "numbered").CombinedOutput()
	outputStr := string(out)

	status := &FirewallStatus{
		Enabled: false,
		Rules:   []FirewallRule{},
	}

	if err != nil {
		// If ufw is not found or inactive
		if strings.Contains(strings.ToLower(outputStr), "inactive") {
			return status, nil
		}
		return status, fmt.Errorf("ufw status: %s (%w)", outputStr, err)
	}

	if strings.Contains(strings.ToLower(outputStr), "status: active") {
		status.Enabled = true
	}

	// Example numbered line:
	// [ 1] 22/tcp                     ALLOW IN    Anywhere
	// [ 2] 8443                       ALLOW IN    Anywhere                   # Bee Panel Admin
	re := regexp.MustCompile(`^\[\s*(\d+)\]\s+(.*?)\s+(ALLOW IN|DENY IN|ALLOW|DENY|REJECT)\s+(.*?)(?:\s+#\s*(.*))?$`)

	scanner := bufio.NewScanner(strings.NewReader(outputStr))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		matches := re.FindStringSubmatch(line)
		if len(matches) >= 5 {
			num, _ := strconv.Atoi(matches[1])
			to := strings.TrimSpace(matches[2])
			action := strings.TrimSpace(matches[3])
			from := strings.TrimSpace(matches[4])
			comment := ""
			if len(matches) >= 6 {
				comment = strings.TrimSpace(matches[5])
			}

			proto := "any"
			if strings.Contains(to, "/tcp") {
				proto = "tcp"
			} else if strings.Contains(to, "/udp") {
				proto = "udp"
			}

			status.Rules = append(status.Rules, FirewallRule{
				Number:   num,
				To:       to,
				Action:   action,
				From:     from,
				Comment:  comment,
				Protocol: proto,
			})
		}
	}

	return status, nil
}

// AddRule adds an allow or deny rule to UFW
func (m *FirewallManager) AddRule(port string, proto string, action string, from string, comment string) error {
	port = strings.TrimSpace(port)
	action = strings.ToLower(strings.TrimSpace(action))
	proto = strings.ToLower(strings.TrimSpace(proto))
	from = strings.TrimSpace(from)

	actStr := "allow"
	if action == "deny" {
		actStr = "deny"
	}

	var args []string
	args = append(args, actStr)

	isSpecificFrom := from != "" && !strings.EqualFold(from, "anywhere") && !strings.EqualFold(from, "any")

	if isSpecificFrom {
		// Syntax: ufw allow from <IP/CIDR> to any port <PORT> [proto <PROTO>]
		args = append(args, "from", from, "to", "any", "port", port)
		if proto == "tcp" || proto == "udp" {
			args = append(args, "proto", proto)
		}
	} else {
		// Syntax: ufw allow <PORT>[/<PROTO>]
		ruleSpec := port
		if proto == "tcp" || proto == "udp" {
			if !strings.Contains(port, "/") {
				ruleSpec = fmt.Sprintf("%s/%s", port, proto)
			}
		}
		args = append(args, ruleSpec)
	}

	if comment != "" {
		args = append(args, "comment", comment)
	}

	cmd := exec.Command("ufw", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ufw error: %s (%w)", string(out), err)
	}
	return nil
}

// DeleteRule deletes a numbered rule from UFW
func (m *FirewallManager) DeleteRule(ruleNum int) error {
	if ruleNum <= 0 {
		return fmt.Errorf("invalid rule number: %d", ruleNum)
	}
	cmd := exec.Command("ufw", "--force", "delete", strconv.Itoa(ruleNum))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ufw delete error: %s (%w)", string(out), err)
	}
	return nil
}

// Toggle enables or disables UFW
func (m *FirewallManager) Toggle(enable bool) error {
	var cmd *exec.Cmd
	if enable {
		cmd = exec.Command("ufw", "--force", "enable")
	} else {
		cmd = exec.Command("ufw", "disable")
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ufw toggle error: %s (%w)", string(out), err)
	}
	return nil
}

// Reload reloads UFW configuration
func (m *FirewallManager) Reload() error {
	cmd := exec.Command("ufw", "reload")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ufw reload error: %s (%w)", string(out), err)
	}
	return nil
}
