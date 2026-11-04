package api

import "testing"

func TestCleanDomainFQDN(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"http://app.example.com", "app.example.com"},
		{"https://app.example.com/", "app.example.com"},
		{"HTTP://MY-DOMAIN.COM/blog/post", "my-domain.com"},
		{"panel.example.com:8443", "panel.example.com"},
		{"  sub.domain.org/  ", "sub.domain.org"},
		{"simple.com", "simple.com"},
	}

	for _, tt := range tests {
		got := cleanDomainFQDN(tt.input)
		if got != tt.expected {
			t.Errorf("cleanDomainFQDN(%q) = %q, expected %q", tt.input, got, tt.expected)
		}
	}
}
