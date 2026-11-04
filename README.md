# 🐝 Bee Panel

> **Multi-Tenant Rootless Server Provisioner & Dynamic Reverse Proxy Engine**  
> Ultra-lightweight Control Plane (Single Static Go Binary) for managing Linux servers (Ubuntu 22.04 LTS, 24.04 LTS, and Debian 12+) with a baseline as low as 1 vCPU / 1GB RAM.

---

## ⚡ One-Line Automated Installer

Compatible with **Ubuntu (22.04 LTS, 24.04 LTS)** and **Debian 12+**:

```bash
curl -fsSL https://raw.githubusercontent.com/tonyzidc/bee-panel/main/scripts/install.sh | bash
```

During installation, the script automatically:
- Checks and upgrades OS packages (`apt-get upgrade`).
- Applies kernel sysctl tuning (`somaxconn`, `inotify`, `swappiness=10`, `unprivileged_port_start=80`).
- Configures a 2GB Swapfile to protect against Out-Of-Memory (OOM) crashes on 1GB VPS instances.
- Installs and enables **UFW Firewall** and **Fail2ban** intrusion defense by default.
- Sets up baseline firewall rules allowing SSH, HTTP (`80`), HTTPS (`443`), Admin (`8443`), Developer Portal (`3000`), and Container Ports (`10000:60000/tcp`).

After successful installation, access:
- 🌐 **Admin Console**: `http://<SERVER_IP>:8443` (Interactive first-time administrator initialization wizard)
- ⚡ **Developer User Portal**: `http://<SERVER_IP>:3000` (Dedicated developer gateway)

---

## 🚀 Key Features

1. **Zero-Root Containerization (User Namespaces)**:
   - Each tenant runs an independent Rootless Docker Daemon (`/run/user/<UID>/docker.sock`).
   - Container breakouts cannot penetrate the host kernel.
   - High-performance **`pasta`** network driver reduces CPU overhead and delivers 5-6x the network throughput of `slirp4netns`.

2. **Clean Light Mode UI Only**:
   - Modern, high-contrast, professional Light Theme UI for both Admin Console and Developer Portal.

3. **Built-in Security Management (Firewall & Fail2ban)**:
   - **UFW Firewall Management**: Toggle firewall, add/delete custom rules (port, protocol, action, comment) directly in the UI.
   - **Fail2ban Intrusion Defense**: Monitor active jails, view currently banned IPs, ban IPs manually, and unban IPs with 1 click.

4. **Global Container Explorer**:
   - Discovers and lists all Docker containers across all isolated rootless tenant sockets in real time.
   - 1-click container actions: **Start**, **Stop**, **Restart**, and **Live Container Logs**.

5. **Edge Nginx Reverse Proxy, ACME SSL & Live Logs**:
   - Route domain names to internal tenant container ports.
   - Automated Let's Encrypt SSL certificate issuance and auto-renewal.
   - Support for custom SSL certificate/key upload.
   - Interactive Nginx **Access Log** and **Error Log** viewer.

6. **Comprehensive User & Credentials Management**:
   - Full CRUD on tenant accounts (Create, View, Suspend/Activate, Delete).
   - View, copy, or download the full **OpenSSH Ed25519 Private Key** (`.pem`), Public Key, and system passwords anytime.
   - Change tenant passwords and rotate SSH keys on demand.

7. **Real-time Dashboard Metrics**:
   - Live CPU Usage %, CPU core count, and system load averages.
   - Memory (RAM) usage, Swap space usage, and Disk storage.
   - Active tenant and container counters with live security status badges.

8. **Comprehensive Settings & Self-Update**:
   - Full panel configuration editor (`/etc/bee-panel/bee-panel.yaml`).
   - **Telegram Event Notifications**: Instant alerts for admin logins, tenant provisioning, SSL certificates, and security alarms with built-in "Send Test Notification".
   - **Safe Host SSH Port Modification**: Change OpenSSH port with automated UFW allow and syntax validation before restarting the SSH service.
   - **GitHub Release Integration**: 1-click update checker and self-updater.

---

## 🛠️ Unified Host CLI Suite

Bee Panel includes a comprehensive host command-line interface:

```bash
# Check version and system architecture
bee-panel version

# Display panel daemon status and metrics
bee-panel status

# Control systemd daemon service
bee-panel start
bee-panel stop
bee-panel restart

# Stream realtime journalctl logs
bee-panel logs -f

# Check or apply automated self-updates from GitHub
bee-panel update --check
bee-panel update

# Reset administrator password directly in the database
bee-panel admin reset-password [username]

# Manage tenants
bee-panel tenant list
bee-panel tenant create <username>
bee-panel tenant info <username>
bee-panel tenant restart <username>
bee-panel tenant delete <username>

# Manage firewall
bee-panel firewall status
bee-panel firewall allow 8080/tcp
bee-panel firewall deny 8080/tcp

# Display full CLI help
bee-panel help
```

---

## 📄 License

MIT License.
