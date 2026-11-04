package proxy

import (
	"strings"
	"testing"

	"bee-panel/templates"
)

func TestRenderVHostStaticVsProxy(t *testing.T) {
	nm := NewNginxManager("/tmp/avail", "/tmp/enabled", "/var/www/bee-acme", templates.NginxVHostTemplate)

	// Case 1: TargetContainerPort > 0 -> should proxy_pass
	cfgProxy := &VHostConfig{
		Domain:              "proxy.example.com",
		ExternalPort:        80,
		TargetContainerPort: 3000,
		EnableSSL:           false,
		WebRoot:             "/home/dev/web/proxy.example.com/public_html",
	}

	renderedProxy, err := nm.RenderVHost(cfgProxy)
	if err != nil {
		t.Fatalf("RenderVHost proxy failed: %v", err)
	}
	if !strings.Contains(renderedProxy, "proxy_pass http://127.0.0.1:3000;") {
		t.Errorf("expected proxy_pass in rendered config, got:\n%s", renderedProxy)
	}

	// Case 2: TargetContainerPort == 0 -> should serve static files from WebRoot
	cfgStatic := &VHostConfig{
		Domain:              "static.example.com",
		ExternalPort:        80,
		TargetContainerPort: 0,
		EnableSSL:           false,
		WebRoot:             "/home/dev/web/static.example.com/public_html",
	}

	renderedStatic, err := nm.RenderVHost(cfgStatic)
	if err != nil {
		t.Fatalf("RenderVHost static failed: %v", err)
	}
	if strings.Contains(renderedStatic, "proxy_pass") {
		t.Errorf("expected NO proxy_pass for static domain, got:\n%s", renderedStatic)
	}
	if !strings.Contains(renderedStatic, "root /home/dev/web/static.example.com/public_html;") {
		t.Errorf("expected root webroot directive in static config, got:\n%s", renderedStatic)
	}
	if !strings.Contains(renderedStatic, "try_files $uri $uri/ /index.html;") {
		t.Errorf("expected try_files directive in static config, got:\n%s", renderedStatic)
	}
}
