# 🐝 Bee Panel v2

> **Ultra-Lightweight Native Rust Reverse Proxy & Linux Host Account Provisioner**  
> *A high-performance, single-binary, drop-in native alternative to Nginx Proxy Manager (NPM).*  
> Designed for Linux servers (Ubuntu 22.04/24.04, Debian 12+, RHEL 9+, Alpine) with baseline memory usage as low as **~15MB RAM**.

---

## ⚡ One-Line Automated Installer

Compatible with **Ubuntu (22.04 LTS, 24.04 LTS)**, **Debian 12+**, and **RHEL 9+**:

```bash
curl -fsSL https://raw.githubusercontent.com/tonyzidc/bee-panel/main/scripts/install.sh | bash
```

During installation, the script automatically:
- Installs native `nginx` and dependencies directly on the host (no Docker required).
- Deploys the static binary `bee-panel` to `/usr/local/bin/bee-panel`.
- Configures `/etc/nginx/nginx.conf` with HTTP proxy hosts and Layer 4 TCP/UDP stream blocks.
- Configures systemd daemon service `/etc/systemd/system/bee-panel.service`.
- Applies UFW firewall rules for SSH (`22`), HTTP (`80`), HTTPS (`443`), and Panel UI (`8443`).

After installation, access:
- 🌐 **Web Dashboard**: `http://<SERVER_IP>:8443`
- 👤 **Default User**: `admin`
- 🔑 **Default Password**: `admin`

---

## 📊 Comparison: Bee Panel v2 vs Nginx Proxy Manager (NPM)

| Metric / Capability | Nginx Proxy Manager (NPM) | Bee Panel v2 (Rust Native) |
| :--- | :--- | :--- |
| **Runtime Architecture** | Docker Container (Node.js + Python + MySQL) | **Single Static Rust Binary** (`axum` + `tokio`) |
| **Memory Footprint (RAM)**| **~400MB - 800MB RAM** | **~15MB - 25MB RAM** (*20x lighter*) |
| **Startup Time** | 10 - 20 seconds | **< 10 milliseconds** |
| **SSL / TLS Engine** | Python Certbot wrapper in container | **Pure Rust ACME Engine** (`instant-acme` + `rcgen`) |
| **Database** | MySQL / SQLite via Knex.js | **Embedded SQLite in WAL Mode** (Zero maintenance) |
| **OS User & SSH Sync** | ❌ None (Web-only accounts) | ✅ **Auto Linux OS Provisioning + Ed25519 SSH Key & Password** |
| **Host Metrics** | ❌ None | ✅ **Live CPU, RAM, Disk & Nginx Engine metrics** |
| **Layer 4 Streams** | TCP / UDP proxying | TCP / UDP proxying with native Nginx stream block |

---

## 🚀 Key Features

### 1. Full Reverse Proxy Engine (100% NPM Parity)
- **Proxy Hosts**: Route multiple domains to backend endpoints with HTTP/HTTPS upstream, custom ports, and path preserving.
- **Asset Caching**: Enable Nginx edge caching (`proxy_cache`) with custom cache timeouts.
- **Exploit Defense**: Built-in blocking of common exploit patterns (SQL injection, XSS, malicious queries, path traversal).
- **WebSockets Support**: Out-of-the-box WebSocket upgrade headers.
- **Custom Locations**: Define subpath routing overrides (`/api`, `/static`) with separate upstream ports and headers.
- **Advanced Configuration**: Inject custom Nginx directives directly per host.

### 2. Pure Rust ACME SSL Engine (Let's Encrypt / ZeroSSL)
- Zero dependency on Python or Certbot.
- Automatic **HTTP-01 Challenge** via Nginx webroot directory (`/var/lib/bee-panel/acme-challenges`).
- Automatic certificate renewal background worker running every 12 hours.
- Custom SSL certificate upload (PEM fullchain & private key).
- Force SSL, HSTS, and HTTP/2 support.

### 3. Automatic Linux User & SSH Key Provisioning (Option A)
- Creating a user in Bee Panel automatically creates a real Linux OS user account on the host.
- Automatically generates an **OpenSSH Ed25519 Key Pair** (`.pem`) and secure system password.
- Injects public key into `/home/<username>/.ssh/authorized_keys` with strict permissions (`700/600`).
- Configurable OS Isolation Modes:
  - **SFTP Only**: Chroot/Restricted web access to `/var/www/vhosts/<username>` (no interactive shell).
  - **Standard Shell**: `/bin/bash` terminal access without sudo.
  - **Sudo Admin**: Full administrative root shell access.
- 1-Click SSH key download, password reveal, and key rotation directly in the Web UI.

### 4. Layer 4 Streams (TCP / UDP Forwarding)
- Forward incoming host ports to internal or external services (MySQL `3306`, PostgreSQL `5432`, Redis `6379`, Game servers, VPNs).
- Simultaneous TCP and UDP listening support.

### 5. Redirections & 404 Dead Hosts
- Chained HTTP redirections (`301 Moved Permanently`, `302 Found`, `307`, `308`).
- Custom maintenance and 404 response pages for inactive or parked domains.

### 6. Access Lists & Intrusion Defense
- IP Whitelisting and Blacklisting with CIDR subnet support (`192.168.1.0/24`).
- HTTP Basic Authentication credentials managed via Nginx `auth_basic`.

---

## 🛠️ Host CLI Suite

Bee Panel v2 includes an ultra-fast host command-line interface:

```bash
# Start the web daemon
bee-panel serve

# Display real-time system and proxy engine metrics
bee-panel status

# Reset administrator password directly in the database
bee-panel reset-password admin

# List all provisioned OS users and their SSH public key fingerprints
bee-panel user-list
```

---

## 🏗️ Architecture

```
bee-panel/
├── Cargo.toml               # Native Rust dependencies
├── src/
│   ├── main.rs              # CLI suite & Axum web entry point
│   ├── config.rs            # Configuration loader (/etc/bee-panel/config.yaml)
│   ├── db/                  # SQLite WAL connection pool & embedded schema
│   ├── core/
│   │   ├── ssh_user.rs      # Ed25519 keygen & Linux OS user provisioner
│   │   ├── nginx.rs         # Minijinja templates, atomic config writes & zero-downtime reload
│   │   ├── acme.rs          # Pure Rust ACME client (RFC 8555)
│   │   └── metrics.rs       # sysinfo host metrics collector
│   ├── api/                 # RESTful API endpoints
│   └── web/                 # Embedded single-page application assets (rust-embed)
├── templates/nginx/         # Minijinja template files for Nginx .conf files
├── tests/                   # Automated unit & integration tests
└── scripts/
    └── install.sh           # One-line installer
```

---

## 📜 License

Licensed under the MIT License.
