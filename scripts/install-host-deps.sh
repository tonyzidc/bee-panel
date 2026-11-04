#!/usr/bin/env bash
# ==============================================================================
# Bee Panel - Host Dependencies & Optimization Installer
# Target OS: Ubuntu 22.04 / 24.04 LTS, Debian 12+
# ==============================================================================
set -euo pipefail

echo "=========================================================="
echo "🐝 Bee Panel - Host Environment Preparation"
echo "=========================================================="

if [ "$(id -u)" -ne 0 ]; then
    echo "❌ Lỗi: Script này phải chạy dưới quyền root (sudo)!" >&2
    exit 1
fi

# 1. OS Validation
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID="$ID"
    OS_VER="${VERSION_ID:-0}"
else
    echo "❌ Lỗi: Không thể xác định hệ điều hành!" >&2
    exit 1
fi

echo "🔍 Phát hiện hệ điều hành: $NAME ($VERSION)"
SUPPORTED=false
if [ "$OS_ID" = "ubuntu" ]; then
    MAJOR_VER=$(echo "$OS_VER" | cut -d. -f1)
    if [ "$MAJOR_VER" -ge 22 ]; then
        SUPPORTED=true
    fi
elif [ "$OS_ID" = "debian" ]; then
    MAJOR_VER=$(echo "$OS_VER" | cut -d. -f1)
    if [ "$MAJOR_VER" -ge 12 ]; then
        SUPPORTED=true
    fi
fi

if [ "$SUPPORTED" = false ]; then
    echo "❌ Lỗi: Bee Panel chỉ hỗ trợ Ubuntu 22.04+ và Debian 12+!" >&2
    exit 1
fi

# 2. Swapfile Optimization (2GB for Low-RAM VPS)
CURRENT_SWAP=$(free -m | awk '/Swap:/ {print $2}')
if [ "$CURRENT_SWAP" -lt 1024 ]; then
    echo "⚙️ Thiết lập Swapfile 2GB để tối ưu RAM..."
    if [ ! -f /swapfile ]; then
        fallocate -l 2G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=2048
        chmod 600 /swapfile
        mkswap /swapfile
        swapon /swapfile
        if ! grep -q '/swapfile' /etc/fstab; then
            echo '/swapfile none swap sw 0 0' >> /etc/fstab
        fi
    else
        swapon /swapfile 2>/dev/null || true
    fi
    # Set swappiness = 10
    sysctl vm.swappiness=10
    if ! grep -q 'vm.swappiness' /etc/sysctl.conf; then
        echo 'vm.swappiness=10' >> /etc/sysctl.conf
    fi
    echo "✅ Đã kích hoạt Swapfile 2GB thành công."
else
    echo "✅ Swapfile hiện có: ${CURRENT_SWAP}MB (Đạt yêu cầu)."
fi

# 3. Disable heavy unused services on low memory
echo "🧹 Dọn dẹp tiến trình tiêu tốn RAM..."
systemctl stop snapd.service snapd.socket 2>/dev/null || true
systemctl disable snapd.service snapd.socket 2>/dev/null || true

# 4. Install Core System Tools & Networking Drivers
echo "📦 Cập nhật package repositories và cài đặt dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    uidmap \
    dbus-user-session \
    passt \
    nginx \
    certbot \
    python3-certbot-nginx \
    tar \
    jq

# 5. Install Official Docker CE (Rootless packages)
echo "🐳 Kiểm tra và cài đặt Docker Rootless Utilities..."
if ! command -v dockerd-rootless-setuptool.sh >/dev/null 2>&1; then
    mkdir -p /etc/apt/keyrings
    if [ ! -f /etc/apt/keyrings/docker.gpg ]; then
        curl -fsSL "https://download.docker.com/linux/$OS_ID/gpg" | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        chmod a+r /etc/apt/keyrings/docker.gpg
    fi
    
    ARCH=$(dpkg --print-architecture)
    CODENAME="${VERSION_CODENAME:-noble}"
    echo "deb [arch=$ARCH signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$OS_ID $CODENAME stable" > /etc/apt/sources.list.d/docker.list
    
    apt-get update -y
    apt-get install -y --no-install-recommends docker-ce docker-ce-cli containerd.io docker-ce-rootless-extras docker-compose-plugin
fi

# Disable default host root docker daemon to save RAM (each tenant runs rootless docker)
echo "🛑 Tắt Docker daemon root mặc định (để tiết kiệm RAM)..."
systemctl stop docker.service docker.socket containerd.service 2>/dev/null || true
systemctl disable docker.service docker.socket containerd.service 2>/dev/null || true

# 6. Verify pasta / passt
if command -v pasta >/dev/null 2>&1; then
    echo "✅ Pasta network driver đã sẵn sàng: $(pasta --version | head -n1)"
else
    echo "⚠️ Cảnh báo: pasta chưa tìm thấy trong PATH, kiểm tra lại gói passt!"
fi

# 7. Configure Nginx ACME webroot directory
echo "🌐 Chuẩn bị thư mục Webroot cho ACME SSL..."
mkdir -p /var/www/bee-acme
chown -R www-data:www-data /var/www/bee-acme
chmod 755 /var/www/bee-acme

# Nginx baseline optimization
echo "⚡ Tối ưu cấu hình Nginx baseline..."
cat << 'EOF' > /etc/nginx/conf.d/bee-baseline.conf
# Bee Panel Nginx Low-Footprint Baseline
server_tokens off;
client_max_body_size 64M;
EOF

nginx -t && systemctl restart nginx
systemctl enable nginx

echo "=========================================================="
echo "🎉 Hoàn tất chuẩn bị môi trường Host cho Bee Panel!"
echo "=========================================================="
