#!/usr/bin/env bash
# ==============================================================================
# Bee Panel - One-Line Universal Installer
# Compatible with: Ubuntu 22.04+, 24.04+, Debian 12+
# ==============================================================================
set -euo pipefail

echo "=========================================================="
echo "🐝 Starting Bee Panel Control Plane Installation"
echo "=========================================================="

if [ "$(id -u)" -ne 0 ]; then
    echo "❌ Error: This script must be run as root (sudo)!" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 1. Execute Host Dependencies & Optimization Installer
if [ -f "$SCRIPT_DIR/install-host-deps.sh" ]; then
    bash "$SCRIPT_DIR/install-host-deps.sh"
else
    TMP_DEPS=$(mktemp)
    curl -fsSL "https://raw.githubusercontent.com/tonyzidc/bee-panel/main/scripts/install-host-deps.sh" -o "$TMP_DEPS" || true
    if [ -s "$TMP_DEPS" ]; then
        bash "$TMP_DEPS"
        rm -f "$TMP_DEPS"
    fi
fi

# 2. Install bee-panel binary
ARCH=$(dpkg --print-architecture)
echo "📦 Configuring binary for architecture: $ARCH..."

if [ -f "$SCRIPT_DIR/../bin/bee-panel-linux-$ARCH" ]; then
    cp "$SCRIPT_DIR/../bin/bee-panel-linux-$ARCH" /usr/local/bin/bee-panel
elif [ -f "$SCRIPT_DIR/bee-panel-linux-$ARCH" ]; then
    cp "$SCRIPT_DIR/bee-panel-linux-$ARCH" /usr/local/bin/bee-panel
elif [ -f "/root/bee-panel-linux-$ARCH" ]; then
    cp "/root/bee-panel-linux-$ARCH" /usr/local/bin/bee-panel
else
    # Fallback download from latest GitHub Release
    echo "⬇️ Downloading latest release binary from GitHub..."
    curl -fsSL "https://github.com/tonyzidc/bee-panel/releases/latest/download/bee-panel-linux-$ARCH" -o /usr/local/bin/bee-panel || true
fi

chmod +x /usr/local/bin/bee-panel

# 3. Create required runtime directories and default config
mkdir -p /var/lib/bee-panel /etc/bee-panel /etc/nginx/sites-available /etc/nginx/sites-enabled /var/www/bee-acme

if [ ! -f /etc/bee-panel/bee-panel.yaml ]; then
    echo "⚙️ Creating default /etc/bee-panel/bee-panel.yaml configuration..."
    cat << 'EOF' > /etc/bee-panel/bee-panel.yaml
server:
  admin_port: 8443
  host: "0.0.0.0"
  jwt_secret: "bee-panel-default-secret-key-32-chars-long"
  jwt_expiry_hours: 72

storage:
  db_path: "/var/lib/bee-panel/bee-panel.db"

ports:
  min_port: 10000
  max_port: 60000

proxy:
  nginx_conf_dir: "/etc/nginx/sites-available"
  nginx_enabled_dir: "/etc/nginx/sites-enabled"
  acme_webroot: "/var/www/bee-acme"

docker:
  network_driver: "pasta"

telegram:
  enabled: false
  bot_token: ""
  chat_id: ""
  notify_on_login: true
  notify_on_tenant_created: true
  notify_on_ssl: true
  notify_on_security: true
EOF
fi

# 4. Register Systemd Unit Service
echo "⚙️ Configuring Systemd Service (bee-panel.service)..."
cat << 'EOF' > /etc/systemd/system/bee-panel.service
[Unit]
Description=Bee Panel Control Plane Daemon
After=network.target nginx.service

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/bee-panel -config /etc/bee-panel/bee-panel.yaml
Restart=always
RestartSec=3s
Environment="GOMEMLIMIT=48MiB"
MemoryMax=80M
MemoryHigh=64M
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now bee-panel.service

# 5. Detect Public IP and Display Finish Banner
HOST_IP=$(curl -s -4 --max-time 3 https://ifconfig.me || curl -s -4 --max-time 3 https://icanhazip.com || hostname -I | awk '{print $1}')

echo ""
echo "=================================================================="
echo "🎉 SUCCESS: Bee Panel has been installed and started successfully!"
echo "=================================================================="
echo ""
echo "🌐 Bee Panel Control Plane (Unified Web Port):"
echo "   👉 Admin Console:     http://${HOST_IP}:8443"
echo "   👉 Developer Portal:  http://${HOST_IP}:8443/portal"
echo ""
echo "📋 Manage daemon service:"
echo "   bee-panel status"
echo "   systemctl status bee-panel"
echo "   journalctl -u bee-panel -f"
echo "=================================================================="
