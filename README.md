# 🐝 Bee Panel

> **Multi-Tenant Rootless Server Provisioner & Dynamic Reverse Proxy Engine**  
> Control Plane siêu nhẹ (Single Static Binary bằng Go) quản lý máy chủ Linux Ubuntu/Debian cấu hình tối thiểu từ 1 Core / 1GB RAM.

---

## ⚡ Cài đặt 1 dòng lệnh (One-Line Installer)

Hỗ trợ **Ubuntu (22.04 LTS, 24.04 LTS)** và **Debian 12+**:

```bash
curl -fsSL https://raw.githubusercontent.com/tonyzidc/bee-panel/main/scripts/install.sh | bash
```

Sau khi cài đặt thành công, truy cập:
- 🌐 **Admin Console**: `http://<SERVER_IP>:8443` (Tự động hiển thị màn hình khởi tạo tài khoản Admin ban đầu)
- ⚡ **Developer User Portal**: `http://<SERVER_IP>:3000` (Cổng kết nối dành cho Tenant/Developer)

---

## 🚀 Tính năng cốt lõi

1. **Zero-Root Containerization (User Namespaces)**:
   - Mỗi tenant sở hữu một Docker Daemon độc lập chạy ở User Space (`/run/user/<UID>/docker.sock`).
   - Container escape không thể chạm tới host kernel.
   - Sử dụng driver mạng **`pasta`** hiệu năng cao, giảm tải CPU và tăng tốc throughput mạng gấp 5-6 lần so với `slirp4netns`.

2. **Dual-Port Isolation**:
   - Cổng Admin (`:8443`) và Cổng User (`:3000`) chạy trên hai engine định tuyến độc lập, tách biệt context và authentication.

3. **Edge Nginx & ACME SSL Đa Cổng**:
   - Cho phép map domain ra cả port chuẩn `80/443` lẫn các cổng tùy biến (ví dụ `8080`, `8888`, `30001`).
   - Cấp phát và tự động gia hạn chứng chỉ Let's Encrypt qua Webroot Challenge.

4. **Low-Footprint Baseline**:
   - Daemon Go nhúng toàn bộ frontend Vue 3 tĩnh qua `//go:embed`, chiếm chưa tới **2MB RAM** khi idle.
   - Tự động thiết lập Swapfile 2GB (`vm.swappiness=10`) chống crash OOM trên các VPS 1GB RAM.
   - Giới hạn cgroups `MemoryMax=80M` và `GOMEMLIMIT=48MiB`.

5. **Atomic Provisioning & Rollback**:
   - Quy trình tạo tenant 6 bước với cơ chế rollback ngược tức thì nếu có bất kỳ bước nào gặp sự cố, đảm bảo không để lại tài khoản rác (zombie).

---

## 📋 Quản lý dịch vụ Daemon

```bash
# Kiểm tra trạng thái
systemctl status bee-panel

# Xem log realtime
journalctl -u bee-panel -f

# Khởi động lại
systemctl restart bee-panel
```

---

## 🛠️ CLI Utilities

Bee Panel hỗ trợ CLI trực tiếp trên host:

```bash
# Tạo tenant thủ công
bee-panel tenant create <username>

# Xóa dọn sạch tenant (containers, files, subuid)
bee-panel tenant delete <username>

# Xem phiên bản
bee-panel version
```

---

## 📄 License
MIT License.
