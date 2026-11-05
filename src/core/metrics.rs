use serde::{Deserialize, Serialize};
use std::process::Command;
use sysinfo::{CpuRefreshKind, Disks, MemoryRefreshKind, RefreshKind, System};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub hostname: String,
    pub os_name: String,
    pub kernel_version: String,
    pub uptime_seconds: u64,
    pub cpu_count: usize,
    pub cpu_usage_percent: f32,
    pub memory_total_bytes: u64,
    pub memory_used_bytes: u64,
    pub memory_usage_percent: f32,
    pub swap_total_bytes: u64,
    pub swap_used_bytes: u64,
    pub disk_total_bytes: u64,
    pub disk_used_bytes: u64,
    pub disk_usage_percent: f32,
    pub nginx_running: bool,
    pub nginx_version: Option<String>,
}

pub struct MetricsCollector {
    sys: System,
}

impl MetricsCollector {
    pub fn new() -> Self {
        let mut sys = System::new_with_specifics(
            RefreshKind::new()
                .with_cpu(CpuRefreshKind::everything())
                .with_memory(MemoryRefreshKind::everything()),
        );
        sys.refresh_all();
        Self { sys }
    }

    pub fn collect(&mut self) -> SystemMetrics {
        self.sys.refresh_cpu_all();
        self.sys.refresh_memory();

        let hostname = System::host_name().unwrap_or_else(|| "localhost".to_string());
        let os_name = System::long_os_version().unwrap_or_else(|| "Linux".to_string());
        let kernel_version = System::kernel_version().unwrap_or_else(|| "Unknown".to_string());
        let uptime_seconds = System::uptime();
        let cpu_count = self.sys.cpus().len();

        let cpu_usage_percent = self.sys.global_cpu_usage();

        let memory_total_bytes = self.sys.total_memory();
        let memory_used_bytes = self.sys.used_memory();
        let memory_usage_percent = if memory_total_bytes > 0 {
            (memory_used_bytes as f32 / memory_total_bytes as f32) * 100.0
        } else {
            0.0
        };

        let swap_total_bytes = self.sys.total_swap();
        let swap_used_bytes = self.sys.used_swap();

        let disks = Disks::new_with_refreshed_list();
        let mut disk_total_bytes = 0;
        let mut disk_available_bytes = 0;

        for disk in &disks {
            disk_total_bytes += disk.total_space();
            disk_available_bytes += disk.available_space();
        }
        let disk_used_bytes = disk_total_bytes.saturating_sub(disk_available_bytes);
        let disk_usage_percent = if disk_total_bytes > 0 {
            (disk_used_bytes as f32 / disk_total_bytes as f32) * 100.0
        } else {
            0.0
        };

        // Check Nginx status
        let nginx_version_out = Command::new("nginx").arg("-v").output().ok();
        let nginx_running = Command::new("pgrep")
            .arg("nginx")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        let nginx_version = nginx_version_out.and_then(|o| {
            let s = String::from_utf8_lossy(&o.stderr).trim().to_string();
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        });

        SystemMetrics {
            hostname,
            os_name,
            kernel_version,
            uptime_seconds,
            cpu_count,
            cpu_usage_percent,
            memory_total_bytes,
            memory_used_bytes,
            memory_usage_percent,
            swap_total_bytes,
            swap_used_bytes,
            disk_total_bytes,
            disk_used_bytes,
            disk_usage_percent,
            nginx_running,
            nginx_version,
        }
    }
}
