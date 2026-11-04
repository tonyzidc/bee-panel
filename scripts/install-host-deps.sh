#!/usr/bin/env bash
# ==============================================================================
# Bee Panel - Host Environment Preparation & Kernel Optimization
# Target OS: Ubuntu 22.04 / 24.04 LTS, Debian 12+
# ==============================================================================
set -euo pipefail

echo "=========================================================="
echo "🐝 Bee Panel - Host Environment Preparation & Optimization"
echo "=========================================================="

if [ "$(id -u)" -ne 0 ]; then
    echo "❌ Error: This script must be run as root (sudo)!" >&2
    exit 1
fi

# 1. OS Validation
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID="$ID"
    OS_VER="${VERSION_ID:-0}"
else
    echo "❌ Error: Cannot determine host operating system!" >&2
    exit 1
fi

echo "🔍 Detected OS: $NAME ($VERSION)"
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
    echo "❌ Error: Bee Panel currently only supports Ubuntu 22.04+ and Debian 12+!" >&2
    exit 1
fi

# 2. Automated OS Package Update & Upgrade
echo "🔄 Updating package repositories and upgrading OS packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"

# 3. Swapfile Optimization (2GB for Low-RAM VPS)
CURRENT_SWAP=$(free -m | awk '/Swap:/ {print $2}')
if [ "$CURRENT_SWAP" -lt 1024 ]; then
    echo "⚙️ Setting up 2GB Swapfile for memory optimization..."
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
    echo "✅ 2GB Swapfile enabled successfully."
else
    echo "✅ Existing swap space: ${CURRENT_SWAP}MB (Sufficient)."
fi

# 4. Kernel Sysctl & Performance Tuning
echo "⚡ Applying kernel sysctl optimizations..."
cat << 'EOF' > /etc/sysctl.d/99-bee-panel.conf
# Bee Panel Kernel Tuning
vm.swappiness = 10
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
fs.file-max = 2097152
fs.inotify.max_user_watches = 524288
fs.inotify.max_user_instances = 8192
net.ipv4.ip_forward = 1
net.ipv4.ip_unprivileged_port_start = 80
EOF
sysctl -p /etc/sysctl.d/99-bee-panel.conf 2>/dev/null || true

# 5. File Descriptor & Security Limits
echo "⚡ Applying system limits (nofile / nproc)..."
cat << 'EOF' > /etc/security/limits.d/99-bee-panel.conf
* soft nofile 65535
* hard nofile 65535
* soft nproc 65535
* hard nproc 65535
root soft nofile 65535
root hard nofile 65535
EOF

# 6. Disable heavy unused services on low memory
echo "🧹 Disabling redundant snapd background services..."
systemctl stop snapd.service snapd.socket 2>/dev/null || true
systemctl disable snapd.service snapd.socket 2>/dev/null || true

# 7. Install Core System Tools, Security & Drivers
echo "📦 Installing core system dependencies, fail2ban, ufw & network drivers..."
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
    jq \
    ufw \
    fail2ban

# 8. Configure UFW Firewall Baseline
echo "🛡️ Configuring baseline UFW firewall..."
CURRENT_SSH_PORT=$(ss -tlnp | grep sshd | awk '{print $4}' | awk -F: '{print $NF}' | head -n1 || echo "22")
if [ -z "$CURRENT_SSH_PORT" ]; then
    CURRENT_SSH_PORT=22
fi
echo "   Allowing SSH port: $CURRENT_SSH_PORT/tcp..."
ufw allow "$CURRENT_SSH_PORT/tcp" comment 'SSH Access' || true
ufw allow 80/tcp comment 'HTTP Web' || true
ufw allow 443/tcp comment 'HTTPS Web' || true
ufw allow 8443/tcp comment 'Bee Panel Admin Console' || true
ufw allow 3000/tcp comment 'Bee Panel Developer Portal' || true
ufw allow 10000:60000/tcp comment 'Bee Panel Container Port Forward Pool' || true
echo "y" | ufw enable || true

# 9. Configure Fail2ban Baseline
echo "🛡️ Configuring Fail2ban intrusion defense..."
cat << 'EOF' > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
EOF
systemctl enable --now fail2ban
systemctl restart fail2ban || true

# 10. Install Official Docker CE (Rootless packages)
echo "🐳 Checking Docker Rootless packages..."
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
echo "🛑 Disabling default root docker service (to conserve host RAM)..."
systemctl stop docker.service docker.socket containerd.service 2>/dev/null || true
systemctl disable docker.service docker.socket containerd.service 2>/dev/null || true

# 11. Configure Nginx ACME Webroot Directory & Baseline
echo "🌐 Preparing ACME SSL Webroot & Nginx baseline..."
mkdir -p /var/www/bee-acme
chown -R www-data:www-data /var/www/bee-acme
chmod 755 /var/www/bee-acme

cat << 'EOF' > /etc/nginx/conf.d/bee-baseline.conf
# Bee Panel Nginx Baseline Configuration
server_tokens off;
client_max_body_size 128M;
EOF

nginx -t && systemctl restart nginx
systemctl enable nginx

echo "=========================================================="
echo "🎉 Host environment preparation & optimization complete!"
echo "=========================================================="
