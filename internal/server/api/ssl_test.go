package api

import (
	"net"
	"testing"
)

func TestValidIPChecks(t *testing.T) {
	validIPs := []string{
		"64.118.143.89",
		"127.0.0.1",
		"192.168.1.1",
		"2606:4700:4700::1111",
	}
	for _, ip := range validIPs {
		if net.ParseIP(ip) == nil {
			t.Errorf("expected %s to be valid IP", ip)
		}
	}

	invalidIPs := []string{
		"panel.example.com",
		"http://64.118.143.89",
		"64.118.143.999",
		"random_string",
	}
	for _, ip := range invalidIPs {
		if net.ParseIP(ip) != nil {
			t.Errorf("expected %s to be invalid IP", ip)
		}
	}
}
