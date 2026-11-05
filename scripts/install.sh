#!/usr/bin/env bash
# ==============================================================================
# 🐝 Bee Panel v2 - Ultra-lightweight Native Rust Reverse Proxy & Host Manager
# One-Line Automated Installer for Ubuntu, Debian, RHEL, and Alpine
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${YELLOW}====================================================================${NC}"
echo -e "${YELLOW}🐝 Starting Bee Panel v2 Installation (Native Rust & Nginx Engine)...${NC}"
echo -e "${YELLOW}====================================================================${NC}"

# 1. Check Root Privileges
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[ERROR] This installer must be run as root (or via sudo).${NC}"
    exit 1
fi

# 2. Detect OS & Package Manager
if command -v apt-get &>/dev/null; then
    PKG_MANAGER="apt"
elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf"
elif command -v yum &>/dev/null; then
    PKG_MANAGER="yum"
elif command -v apk &>/dev/null; then
    PKG_MANAGER="apk"
else
    echo -e "${RED}[ERROR] Unsupported package manager. Debian, Ubuntu, RHEL or Alpine required.${NC}"
    exit 1
fi

echo -e "${BLUE}[INFO] Detected package manager: ${PKG_MANAGER}${NC}"

# 3. Install Native Nginx and Dependencies
echo -e "${BLUE}[INFO] Installing Nginx and core system dependencies...${NC}"
case "${PKG_MANAGER}" in
    apt)
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq nginx libnginx-mod-stream curl tar openssl ufw
        rm -f /etc/nginx/sites-enabled/default
        ;;
    dnf|yum)
        ${PKG_MANAGER} install -y nginx curl tar openssl firewalld
        ;;
    apk)
        apk update
        apk add nginx curl tar openssl
        ;;
esac

# 4. Prepare Directory Hierarchy
echo -e "${BLUE}[INFO] Creating Bee Panel and Nginx directory structures...${NC}"
mkdir -p /etc/bee-panel
mkdir -p /etc/bee-panel/certs
mkdir -p /etc/nginx/bee-panel/conf.d
mkdir -p /etc/nginx/bee-panel/streams.d
mkdir -p /etc/nginx/bee-panel/access
mkdir -p /var/lib/bee-panel/acme-challenges
mkdir -p /var/www/vhosts

# Ensure permissions
chmod 755 /var/lib/bee-panel/acme-challenges
chmod 755 /var/www/vhosts

# 5. Patch Nginx Main Configuration to Include Bee Panel Vhosts & Streams
NGINX_CONF="/etc/nginx/nginx.conf"
if [ -f "${NGINX_CONF}" ]; then
    # Add stream block if not present
    if ! grep -q "/etc/nginx/bee-panel/streams.d" "${NGINX_CONF}"; then
        cat << 'EOF' >> "${NGINX_CONF}"

# Bee Panel v2 Stream Forwarding (Layer 4 TCP / UDP)
stream {
    include /etc/nginx/bee-panel/streams.d/*.conf;
}
EOF
    fi

    # Include HTTP conf.d if not included
    if ! grep -q "/etc/nginx/bee-panel/conf.d" "${NGINX_CONF}"; then
        sed -i '/http {/a \    include /etc/nginx/bee-panel/conf.d/*.conf;' "${NGINX_CONF}" || true
    fi
fi

# 6. Install or Build Binary
echo -e "${BLUE}[INFO] Installing Bee Panel v2 Native Binary...${NC}"
TARGET_BIN="/usr/local/bin/bee-panel"

# If local cargo target exists (local run), copy it
if [ -f "./target/release/bee-panel" ]; then
    cp ./target/release/bee-panel "${TARGET_BIN}"
elif [ -f "./target/debug/bee-panel" ]; then
    cp ./target/debug/bee-panel "${TARGET_BIN}"
else
    # In production, download pre-built static musl binary from GitHub Releases
    echo -e "${BLUE}[INFO] Downloading latest static binary from GitHub...${NC}"
    ARCH="$(uname -m)"
    case "${ARCH}" in
        x86_64) BIN_ARCH="x86_64-unknown-linux-musl" ;;
        aarch64|arm64) BIN_ARCH="aarch64-unknown-linux-musl" ;;
        *) echo -e "${RED}[ERROR] Unsupported architecture: ${ARCH}${NC}"; exit 1 ;;
    esac

    # Fallback to building locally if cargo is present
    if command -v cargo &>/dev/null; then
        echo -e "${BLUE}[INFO] Compiling native release binary via Cargo...${NC}"
        cargo build --release
        cp target/release/bee-panel "${TARGET_BIN}"
    else
        echo -e "${YELLOW}[WARN] Cargo not detected. Please ensure binary is placed at ${TARGET_BIN}${NC}"
    fi
fi

chmod +x "${TARGET_BIN}"

# 7. Setup Systemd Service
echo -e "${BLUE}[INFO] Creating systemd service /etc/systemd/system/bee-panel.service...${NC}"
cat << 'EOF' > /etc/systemd/system/bee-panel.service
[Unit]
Description=Bee Panel v2 Native Reverse Proxy & Host Daemon
After=network.target nginx.service
Requires=nginx.service

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/bee-panel serve
Restart=always
RestartSec=3
LimitNOFILE=65535
Environment="BEE_HOST=0.0.0.0"
Environment="BEE_PORT=8443"

[Install]
WantedBy=multi-user.target
EOF

if command -v systemctl &>/dev/null; then
    systemctl daemon-reload
    systemctl enable nginx
    systemctl restart nginx || true
    systemctl enable bee-panel
    systemctl restart bee-panel
fi

# 8. Configure UFW Firewall if active
if command -v ufw &>/dev/null; then
    echo -e "${BLUE}[INFO] Opening default ports in UFW (80, 443, 8443, 22)...${NC}"
    ufw allow 80/tcp comment 'Nginx HTTP' || true
    ufw allow 443/tcp comment 'Nginx HTTPS' || true
    ufw allow 8443/tcp comment 'Bee Panel Web UI' || true
    ufw allow 22/tcp comment 'SSH' || true
fi

# 9. Completion Message
SERVER_IP=$(curl -s -4 https://ifconfig.me || hostname -I | awk '{print $1}')
echo -e "\n${GREEN}====================================================================${NC}"
echo -e "${GREEN}🎉 Bee Panel v2 successfully installed!${NC}"
echo -e "${GREEN}====================================================================${NC}"
echo -e "🌐 Web Dashboard:  ${YELLOW}http://${SERVER_IP}:8443${NC}"
echo -e "👤 Default User:   ${YELLOW}admin${NC}"
echo -e "🔑 Default Pass:   ${YELLOW}admin${NC}"
echo -e "\n${BLUE}💡 Next steps:${NC}"
echo -e "  1. Sign in to the dashboard and change the default admin password."
echo -e "  2. Create Users (Option A) to automatically provision Linux SSH keys & passwords."
echo -e "  3. Add Proxy Hosts with instant SSL & Nginx hot reload."
echo -e "${GREEN}====================================================================${NC}\n"
