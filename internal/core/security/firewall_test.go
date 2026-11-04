package security

import "testing"

func TestIsSystemProtectedPort(t *testing.T) {
	adminPort := 8443
	userPort := 3000

	protectedPorts := []int{22, 80, 443, 8443, 3000}
	for _, port := range protectedPorts {
		if !IsSystemProtectedPort(port, adminPort, userPort) {
			t.Errorf("expected port %d to be protected", port)
		}
	}

	nonProtectedPorts := []int{8080, 5000, 18080, 9000, 3306, 6379}
	for _, port := range nonProtectedPorts {
		if IsSystemProtectedPort(port, adminPort, userPort) {
			t.Errorf("expected port %d to NOT be protected", port)
		}
	}
}
