#!/usr/bin/env bash
# ==============================================================================
# Bee Panel - One-Line Universal Installer
# Compatible with: Ubuntu 22.04+, 24.04+, Debian 12+
# ==============================================================================
set -euo pipefail

echo "=========================================================="
echo "🐝 Bắt đầu cài đặt Bee Panel Control Plane"
echo "=========================================================="

if [ "$(id -u)" -ne 0 ]; then
    echo "❌ Lỗi: Script này bắt buộc phải chạy dưới quyền root (sudo)!" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 1. Execute Host Dependencies Installer if locally available or via URL
if [ -f "$SCRIPT_DIR/install-host-deps.sh" ]; then
    bash "$SCRIPT_DIR/install-host-deps.sh"
else
    # Download directly if piped from curl
    TMP_DEPS=$(mktemp)
    curl -fsSL "https://raw.githubusercontent.com/tonyzidc/bee-panel/main/scripts/install-host-deps.sh" -o "$TMP_DEPS" || true
    if [ -s "$TMP_DEPS" ]; then
        bash "$TMP_DEPS"
        rm -f "$TMP_DEPS"
    fi
fi

# 2. Install bee-panel binary
ARCH=$(dpkg --print-architecture)
echo "📦 Cấu hình binary cho kiến trúc: $ARCH..."

if [ -f "$SCRIPT_DIR/../bin/bee-panel-linux-$ARCH" ]; then
    cp "$SCRIPT_DIR/../bin/bee-panel-linux-$ARCH" /usr/local/bin/bee-panel
elif [ -f "$SCRIPT_DIR/bee-panel-linux-$ARCH" ]; then
    cp "$SCRIPT_DIR/bee-panel-linux-$ARCH" /usr/local/bin/bee-panel
elif [ -f "/root/bee-panel-linux-$ARCH" ]; then
    cp "/root/bee-panel-linux-$ARCH" /usr/local/bin/bee-panel
else
    # Fallback download from latest GitHub Release
    echo "⬇️ Đang tải bản phát hành mới nhất từ GitHub..."
    curl -fsSL "https://github.com/tonyzidc/bee-panel/releases/latest/download/bee-panel-linux-$ARCH" -o /usr/local/bin/bee-panel || true
fi

chmod +x /usr/local/bin/bee-panel

# 3. Create required runtime directories
mkdir -p /var/lib/bee-panel /etc/nginx/sites-available /etc/nginx/sites-enabled /var/www/bee-acme

# 4. Register Systemd Unit Service
echo "⚙️ Thiết lập Systemd Service (bee-panel.service)..."
cat << 'EOF' > /etc/systemd/system/bee-panel.service
[Unit]
Description=Bee Panel Control Plane Daemon
After=network.target nginx.service

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/bee-panel
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
echo "🎉 CHÚC MỪNG: Bee Panel đã được cài đặt và khởi chạy thành công!"
echo "=================================================================="
echo ""
echo "🌐 1. Admin Console (Truy cập lần đầu để đăng ký Admin):"
echo "   👉 http://${HOST_IP}:8443"
echo ""
echo "⚡ 2. Developer User Portal (Cổng dành cho lập trình viên):"
echo "   👉 http://${HOST_IP}:3000"
echo ""
echo "📋 Quản lý dịch vụ daemon:"
echo "   systemctl status bee-panel"
echo "   journalctl -u bee-panel -f"
echo "=================================================================="
