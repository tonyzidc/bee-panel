package provisioner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// EnsureDomainWebroot sets up the domain directory hierarchy, default placeholder index.html, and permissions
func EnsureDomainWebroot(domain, homeDir string, uid, gid, targetPort int) (string, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return "", fmt.Errorf("domain cannot be empty")
	}

	var baseDir string
	if homeDir != "" {
		_ = os.Chmod(homeDir, 0711) // Allow webserver traversal while preventing directory listing by others
		webParent := filepath.Join(homeDir, "web")
		if err := os.MkdirAll(webParent, 0755); err != nil {
			return "", fmt.Errorf("create web directory: %w", err)
		}
		if uid > 0 && gid > 0 {
			_ = os.Chown(webParent, uid, gid)
		}
		baseDir = filepath.Join(webParent, domain)
	} else {
		baseDir = filepath.Join("/var/www/vhosts", domain)
	}

	htmlDir := filepath.Join(baseDir, "public_html")
	logsDir := filepath.Join(baseDir, "logs")

	if err := os.MkdirAll(htmlDir, 0755); err != nil {
		return "", fmt.Errorf("create public_html directory: %w", err)
	}
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		return "", fmt.Errorf("create logs directory: %w", err)
	}

	// 1. Create starter index.html if not already existing
	indexPath := filepath.Join(htmlDir, "index.html")
	if _, err := os.Stat(indexPath); os.IsNotExist(err) {
		indexContent := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>%s - Hosted on Bee Panel</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; background-color: #f8fafc; color: #0f172a; }
    .card { background: white; padding: 2.5rem; border-radius: 1rem; border: 1px solid #e2e8f0; box-shadow: 0 10px 15px -3px rgb(0 0 0 / 0.1); max-width: 520px; text-align: center; }
    .badge { display: inline-block; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 700; background: #fef3c7; color: #92400e; margin-bottom: 1rem; }
    h1 { font-size: 1.5rem; margin-bottom: 0.5rem; color: #0f172a; }
    p { font-size: 0.875rem; color: #64748b; line-height: 1.5; margin: 0.5rem 0; }
    .box { background: #f1f5f9; padding: 0.75rem; border-radius: 0.5rem; font-family: monospace; font-size: 0.75rem; color: #0f172a; margin-top: 1rem; word-break: break-all; }
  </style>
</head>
<body>
  <div class="card">
    <span class="badge">🐝 Bee Panel</span>
    <h1>%s</h1>
    <p>This domain is connected to Bee Panel and ready to serve your web application or containers.</p>
    <div class="box">Web Root: %s</div>
  </div>
</body>
</html>
`, domain, domain, htmlDir)
		_ = os.WriteFile(indexPath, []byte(indexContent), 0644)
	}

	// 2. Create sample docker-compose.yml.sample if targetPort > 0
	if targetPort > 0 {
		composePath := filepath.Join(baseDir, "docker-compose.yml.sample")
		if _, err := os.Stat(composePath); os.IsNotExist(err) {
			composeContent := fmt.Sprintf(`# Bee Panel Starter Docker Compose Template
# Connects container port 80 to host port %d
version: '3.8'

services:
  web:
    image: nginx:alpine
    restart: unless-stopped
    ports:
      - "127.0.0.1:%d:80"
    volumes:
      - ./public_html:/usr/share/nginx/html:ro
`, targetPort, targetPort)
			_ = os.WriteFile(composePath, []byte(composeContent), 0644)
		}
	}

	// 3. Set ownership recursively if tenant UID/GID are specified
	if uid > 0 && gid > 0 {
		_ = filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
			if err == nil {
				_ = os.Chown(path, uid, gid)
			}
			return nil
		})
	}

	return htmlDir, nil
}
