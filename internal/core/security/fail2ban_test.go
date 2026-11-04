package security

import (
	"strings"
	"testing"
)

func TestParseBanWithTime(t *testing.T) {
	raw := `2.57.121.112 	2026-11-04 12:33:34 + 3600 = 2026-11-04 13:33:34
193.46.255.86 	2026-11-04 12:35:17 + 3600 = 2026-11-04 13:35:17
`
	list := parseBanTimeOutput("sshd", raw)
	if len(list) != 2 {
		t.Fatalf("expected 2 items, got %d", len(list))
	}
	if list[0].IP != "2.57.121.112" || list[0].BanTime != "2026-11-04 12:33:34" || list[0].ExpireTime != "2026-11-04 13:33:34" {
		t.Errorf("unexpected list[0]: %+v", list[0])
	}
	if list[1].IP != "193.46.255.86" || list[1].BanTime != "2026-11-04 12:35:17" || list[1].ExpireTime != "2026-11-04 13:35:17" {
		t.Errorf("unexpected list[1]: %+v", list[1])
	}
}

func TestExtractAttackForensics(t *testing.T) {
	authLogs := []string{
		"Nov 04 12:35:06 server sshd[36647]: Invalid user support from 193.46.255.86 port 12164",
		"Nov 04 12:35:09 server sshd[36647]: Failed password for invalid user support from 193.46.255.86 port 12164 ssh2",
		"Nov 04 12:35:13 server sshd[36647]: Failed password for invalid user support from 193.46.255.86 port 12164 ssh2",
	}

	attackType, trigger, count := analyzeLogLinesForIP("193.46.255.86", authLogs, nil)
	if count != 3 {
		t.Errorf("expected count 3, got %d", count)
	}
	if !strings.Contains(attackType, "support") {
		t.Errorf("expected attackType containing 'support', got '%s'", attackType)
	}
	if !strings.Contains(trigger, "193.46.255.86") {
		t.Errorf("expected trigger containing IP, got '%s'", trigger)
	}
}
