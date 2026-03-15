/// System-level operations and service discovery.
use crate::models::service::{ServiceHealthState, ServiceInfo, ServiceStatus, ServiceType};
use std::path::Path;
use tokio::process::Command;

/// Get the status of all managed services.
pub async fn get_all_services_status() -> Vec<ServiceInfo> {
    let mut services = Vec::new();

    let service_types = vec![
        ServiceType::OpenLiteSpeed,
        ServiceType::MariaDB,
        ServiceType::Postfix,
        ServiceType::Dovecot,
        ServiceType::Ftpd,
        ServiceType::PhpMyAdmin,
    ];

    for service_type in service_types {
        if let Ok(status) = get_service_status(service_type).await {
            let port = get_service_port(service_type);
            let health_state = probe_service_health(status, port).await;
            services.push(ServiceInfo {
                service_type,
                status,
                health_state,
                port,
                version: get_service_version(service_type).await.ok(),
                uptime_seconds: None,
                last_error: None,
            });
        }
    }

    services
}

/// Probe a service's port to distinguish a running-but-not-serving process from
/// a fully operational one. This catches services that are alive in pgrep but
/// whose port is not yet (or no longer) accepting connections.
async fn probe_service_health(status: ServiceStatus, port: Option<u16>) -> ServiceHealthState {
    use tokio::net::TcpStream;
    use tokio::time::{timeout, Duration};

    match status {
        ServiceStatus::Running => match port {
            Some(p) => {
                let addr = format!("127.0.0.1:{}", p);
                match timeout(Duration::from_millis(500), TcpStream::connect(&addr)).await {
                    Ok(Ok(_)) => ServiceHealthState::FullyOperational,
                    _ => ServiceHealthState::ProcessUpPortClosed,
                }
            }
            // No port to probe (e.g., PHP runs inside OLS, Certbot is a one-shot tool).
            None => ServiceHealthState::FullyOperational,
        },
        ServiceStatus::Stopped | ServiceStatus::Error => ServiceHealthState::Down,
        ServiceStatus::Unknown => ServiceHealthState::Unknown,
    }
}

/// Get the status of a specific service.
/// Uses pgrep as the primary detection method (no root needed), then falls back
/// to systemctl / `service` for services where a process name alone is ambiguous.
pub async fn get_service_status(service_type: ServiceType) -> Result<ServiceStatus, String> {
    // --- Fast path: pgrep process check (works without root in containers) ---
    // This is more reliable than init-script pid-file checks which require root.
    let pgrep_pattern: Option<&str> = match service_type {
        ServiceType::OpenLiteSpeed => Some("lshttpd"), // cmdline contains "lshttpd"
        ServiceType::MariaDB => Some("mysqld"),        // mysqld or mysqld_safe
        ServiceType::Postfix => Some("postfix"),
        ServiceType::Dovecot => Some("dovecot"),
        ServiceType::Ftpd => Some("pure-ftpd"),
        ServiceType::PHP => return Ok(ServiceStatus::Running), // runs inside OLS
        ServiceType::Certbot => return Ok(ServiceStatus::Running),
        ServiceType::PhpMyAdmin => return Ok(ServiceStatus::Running),
        ServiceType::SpamAssassin => Some("spamassassin"),
        ServiceType::Rspamd => Some("rspamd"),
        ServiceType::ClamAV => Some("clamd"),
        ServiceType::MailScanner => Some("MailScanner"),
        ServiceType::Redis => Some("redis-server"),
    };

    if let Some(pattern) = pgrep_pattern {
        // pgrep -f searches the full command line; exit 0 means ≥1 match found.
        if let Ok(out) = Command::new("pgrep").arg("-f").arg(pattern).output().await {
            if out.status.success() {
                return Ok(ServiceStatus::Running);
            }
        }
    }

    // --- Slow path: systemctl / service fallback ---
    let service_name = match service_type {
        ServiceType::OpenLiteSpeed => "lsws",
        ServiceType::MariaDB => "mariadb",
        ServiceType::Postfix => "postfix",
        ServiceType::Dovecot => "dovecot",
        ServiceType::Ftpd => "pure-ftpd",
        ServiceType::PHP | ServiceType::Certbot | ServiceType::PhpMyAdmin => {
            return Ok(ServiceStatus::Running);
        }
        ServiceType::SpamAssassin => "spamassassin",
        ServiceType::Rspamd => "rspamd",
        ServiceType::ClamAV => "clamav-daemon",
        ServiceType::MailScanner => "mailscanner",
        ServiceType::Redis => "redis-server",
    };

    // Try systemctl first (works on systemd systems)
    let output = Command::new("systemctl")
        .arg("is-active")
        .arg(service_name)
        .output()
        .await
        .map_err(|e| e.to_string())?;

    let status_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
    match status_str.as_str() {
        "active" => return Ok(ServiceStatus::Running),
        "inactive" | "failed" => return Ok(ServiceStatus::Stopped),
        _ => {}
    }

    // Fallback: `service <name> status`
    let svc_output = Command::new("service")
        .arg(service_name)
        .arg("status")
        .output()
        .await
        .map_err(|e| e.to_string())?;

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&svc_output.stdout).to_lowercase(),
        String::from_utf8_lossy(&svc_output.stderr).to_lowercase(),
    );

    if combined.contains("is running") || combined.contains("start/running") {
        Ok(ServiceStatus::Running)
    } else if combined.contains("not running")
        || combined.contains("stopped")
        || combined.contains("is not running")
    {
        Ok(ServiceStatus::Stopped)
    } else if svc_output.status.success() {
        Ok(ServiceStatus::Running)
    } else {
        Ok(ServiceStatus::Stopped)
    }
}

/// Get the default port for a service.
pub fn get_service_port(service_type: ServiceType) -> Option<u16> {
    match service_type {
        ServiceType::OpenLiteSpeed => Some(8080),
        ServiceType::MariaDB => Some(3306),
        ServiceType::Postfix => Some(465),
        ServiceType::Dovecot => Some(993),

        ServiceType::Ftpd => Some(21),
        _ => None,
    }
}

/// Get the version of a service.
pub async fn get_service_version(service_type: ServiceType) -> Result<String, String> {
    let version = match service_type {
        ServiceType::OpenLiteSpeed => {
            // lshttpd -v writes to stderr on some builds; try both stdout and stderr.
            let output = Command::new("/usr/local/lsws/bin/lshttpd")
                .arg("-v")
                .output()
                .await
                .map_err(|e| e.to_string())?;
            let raw = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
            raw.lines().next().unwrap_or("").trim().to_string()
        }
        ServiceType::MariaDB => {
            let output = Command::new("mariadb")
                .arg("--version")
                .output()
                .await
                .map_err(|e| e.to_string())?;
            let raw = String::from_utf8_lossy(&output.stdout);
            // Extract version from "mariadb Ver X.X Distrib X.X.X-MariaDB, ..."
            raw.split_whitespace()
                .skip_while(|s| !s.eq_ignore_ascii_case("Distrib"))
                .nth(1)
                .map(|v| v.trim_end_matches(',').to_string())
                .unwrap_or_else(|| raw.trim().to_string())
        }
        ServiceType::Postfix => {
            // `postconf mail_version` emits "mail_version = 3.x.x"
            let output = Command::new("postconf")
                .arg("mail_version")
                .output()
                .await
                .map_err(|e| e.to_string())?;
            let raw = String::from_utf8_lossy(&output.stdout);
            raw.split_once('=')
                .map(|x| x.1.trim().to_string())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "Could not parse postfix version".to_string())?
        }
        ServiceType::Dovecot => {
            // `dovecot --version` emits e.g. "2.3.19.1 (9b53102964)"
            let output = Command::new("dovecot")
                .arg("--version")
                .output()
                .await
                .map_err(|e| e.to_string())?;
            let raw = String::from_utf8_lossy(&output.stdout);
            raw.trim().to_string()
        }
        ServiceType::Ftpd => {
            // pure-ftpd doesn't have a --version flag; read from dpkg.
            let output = Command::new("dpkg")
                .args(["--showformat=${Version}", "-W", "pure-ftpd"])
                .output()
                .await
                .map_err(|e| e.to_string())?;
            let raw = String::from_utf8_lossy(&output.stdout);
            let ver = raw.trim();
            if ver.is_empty() {
                return Err("pure-ftpd not installed".to_string());
            }
            ver.to_string()
        }
        ServiceType::PhpMyAdmin => {
            // Read version from dpkg-query; strip epoch prefix (e.g. "4:5.2.1+dfsg..." → "5.2.1")
            let output = Command::new("dpkg-query")
                .args(["-W", "-f=${Version}", "phpmyadmin"])
                .output()
                .await
                .map_err(|e| e.to_string())?;
            let raw = String::from_utf8_lossy(&output.stdout);
            let ver = raw.trim();
            if ver.is_empty() {
                return Err("phpmyadmin not installed".to_string());
            }
            // Strip epoch ("4:") and Debian suffix ("+dfsg-1+deb12u1")
            let stripped = ver.splitn(2, ':').last().unwrap_or(ver);
            stripped.split('+').next().unwrap_or(stripped).to_string()
        }
        _ => return Err("Version not available".to_string()),
    };

    Ok(version)
}

/// Check if a service is installed.
pub async fn is_service_installed(service_type: ServiceType) -> bool {
    match service_type {
        ServiceType::OpenLiteSpeed => Path::new("/usr/local/lsws/bin/lswsctrl").exists(),
        ServiceType::MariaDB => which("mariadb").await,
        ServiceType::Postfix => which("postfix").await,
        ServiceType::Dovecot => which("dovecot").await,
        ServiceType::Ftpd => which("pure-ftpd").await,
        ServiceType::PHP => Path::new("/usr/local/lsws/lsphp83/bin/lsphp").exists(),
        ServiceType::Certbot => which("certbot").await,
        ServiceType::PhpMyAdmin => Path::new("/usr/share/phpmyadmin/index.php").exists(),
        ServiceType::SpamAssassin => Path::new("/usr/bin/spamassassin").exists(),
        ServiceType::Rspamd => which("rspamd").await,
        ServiceType::ClamAV => which("clamscan").await,
        ServiceType::MailScanner => {
            Path::new("/usr/sbin/MailScanner").exists()
                || Path::new("/usr/lib/MailScanner").exists()
        }
        ServiceType::Redis => which("redis-server").await,
    }
}

/// Check if a binary exists in PATH.
async fn which(binary: &str) -> bool {
    Command::new("which")
        .arg(binary)
        .output()
        .await
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Get system metrics (CPU, RAM, disk).
pub async fn get_system_metrics() -> Result<SystemMetrics, String> {
    use std::fs;

    let meminfo = fs::read_to_string("/proc/meminfo").map_err(|e| e.to_string())?;

    let mut total_mem = 0u64;
    let mut available_mem = 0u64;

    for line in meminfo.lines() {
        if let Some(value) = line.strip_prefix("MemTotal:") {
            total_mem = value
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
        }
        if let Some(value) = line.strip_prefix("MemAvailable:") {
            available_mem = value
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
        }
    }

    let loadavg = fs::read_to_string("/proc/loadavg").map_err(|e| e.to_string())?;
    let loads: Vec<&str> = loadavg.split_whitespace().collect();
    let load_1 = loads
        .first()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0);
    let load_5 = loads
        .get(1)
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0);
    let load_15 = loads
        .get(2)
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0);

    // CPU usage from /proc/stat
    let cpu_usage = get_cpu_usage().await;

    // Disk partitions from df
    let disks = get_disk_partitions().await;

    // Network interfaces from /proc/net/dev
    let network = get_network_stats().await;

    // Docker containers
    let docker = get_docker_containers().await;

    // Uptime
    let uptime_seconds = fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| {
            s.split_whitespace()
                .next()
                .and_then(|v| v.parse::<f64>().ok())
        })
        .map(|v| v as u64)
        .unwrap_or(0);

    // CPU count
    let cpu_cores = fs::read_to_string("/proc/cpuinfo")
        .ok()
        .map(|s| s.lines().filter(|l| l.starts_with("processor")).count() as u32)
        .unwrap_or(1);

    Ok(SystemMetrics {
        total_memory_gb: total_mem as f64 / 1024.0 / 1024.0,
        available_memory_gb: available_mem as f64 / 1024.0 / 1024.0,
        load_1,
        load_5,
        load_15,
        cpu_usage_pct: cpu_usage,
        cpu_cores,
        uptime_seconds,
        disks,
        network,
        docker,
    })
}

/// Measure CPU usage over a brief sample window.
async fn get_cpu_usage() -> f64 {
    use std::fs;
    use tokio::time::{sleep, Duration};

    fn read_cpu_stat() -> Option<(u64, u64)> {
        let stat = fs::read_to_string("/proc/stat").ok()?;
        let cpu_line = stat.lines().next()?;
        let parts: Vec<u64> = cpu_line
            .split_whitespace()
            .skip(1)
            .filter_map(|s| s.parse().ok())
            .collect();
        if parts.len() < 4 {
            return None;
        }
        let total: u64 = parts.iter().sum();
        let idle = parts.get(3).copied().unwrap_or(0);
        Some((total, idle))
    }

    let Some((total1, idle1)) = read_cpu_stat() else {
        return 0.0;
    };
    sleep(Duration::from_millis(250)).await;
    let Some((total2, idle2)) = read_cpu_stat() else {
        return 0.0;
    };

    let total_diff = total2.saturating_sub(total1) as f64;
    let idle_diff = idle2.saturating_sub(idle1) as f64;

    if total_diff > 0.0 {
        ((total_diff - idle_diff) / total_diff * 100.0).clamp(0.0, 100.0)
    } else {
        0.0
    }
}

/// Get disk partition info via df.
async fn get_disk_partitions() -> Vec<DiskPartition> {
    let output = Command::new("df")
        .args([
            "-B1",
            "--output=source,size,used,avail,pcent,target",
            "-x",
            "tmpfs",
            "-x",
            "devtmpfs",
            "-x",
            "overlay",
        ])
        .output()
        .await;

    let Ok(output) = output else { return vec![] };
    let stdout = String::from_utf8_lossy(&output.stdout);

    stdout
        .lines()
        .skip(1) // Skip header
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 6 {
                return None;
            }
            let device = parts[0].to_string();
            // Skip pseudo filesystems
            if device.starts_with("none") || device == "shm" {
                return None;
            }
            let total_bytes: u64 = parts[1].parse().unwrap_or(0);
            let used_bytes: u64 = parts[2].parse().unwrap_or(0);
            let avail_bytes: u64 = parts[3].parse().unwrap_or(0);
            let use_pct: u32 = parts[4].trim_end_matches('%').parse().unwrap_or(0);
            let mount = parts[5].to_string();
            Some(DiskPartition {
                device,
                mount,
                total_gb: total_bytes as f64 / 1_073_741_824.0,
                used_gb: used_bytes as f64 / 1_073_741_824.0,
                avail_gb: avail_bytes as f64 / 1_073_741_824.0,
                use_pct,
            })
        })
        .collect()
}

/// Get network interface stats from /proc/net/dev.
async fn get_network_stats() -> Vec<NetworkInterface> {
    use std::fs;

    let Ok(content) = fs::read_to_string("/proc/net/dev") else {
        return vec![];
    };

    content
        .lines()
        .skip(2) // Skip headers
        .filter_map(|line| {
            let (iface, rest) = line.split_once(':')?;
            let iface = iface.trim().to_string();
            if iface == "lo" {
                return None;
            } // Skip loopback
            let nums: Vec<u64> = rest
                .split_whitespace()
                .filter_map(|s| s.parse().ok())
                .collect();
            if nums.len() < 10 {
                return None;
            }
            Some(NetworkInterface {
                name: iface,
                rx_bytes: nums[0],
                tx_bytes: nums[8],
                rx_packets: nums[1],
                tx_packets: nums[9],
                rx_errors: nums[2],
                tx_errors: nums[10],
            })
        })
        .collect()
}

/// Get docker container list.
async fn get_docker_containers() -> Vec<DockerContainer> {
    let output = Command::new("docker")
        .args([
            "ps",
            "-a",
            "--format",
            "{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.State}}\t{{.Ports}}",
        ])
        .output()
        .await;

    let Ok(output) = output else { return vec![] };
    if !output.status.success() {
        return vec![];
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut containers: Vec<DockerContainer> = stdout
        .lines()
        .filter(|l| !l.is_empty())
        .map(|line| {
            let parts: Vec<&str> = line.splitn(5, '\t').collect();
            DockerContainer {
                name: parts.first().unwrap_or(&"").to_string(),
                image: parts.get(1).unwrap_or(&"").to_string(),
                status: parts.get(2).unwrap_or(&"").to_string(),
                state: parts.get(3).unwrap_or(&"").to_string(),
                ports: parts.get(4).unwrap_or(&"").to_string(),
                cpu_pct: 0.0,
                mem_mb: 0.0,
            }
        })
        .collect();

    // Get resource usage for running containers
    if !containers.is_empty() {
        let stats_output = Command::new("docker")
            .args([
                "stats",
                "--no-stream",
                "--format",
                "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}",
            ])
            .output()
            .await;

        if let Ok(stats) = stats_output {
            let stats_str = String::from_utf8_lossy(&stats.stdout);
            for line in stats_str.lines() {
                let parts: Vec<&str> = line.splitn(3, '\t').collect();
                if parts.len() >= 3 {
                    let name = parts[0];
                    let cpu: f64 = parts[1].trim_end_matches('%').parse().unwrap_or(0.0);
                    let mem_str = parts[2].split('/').next().unwrap_or("0").trim();
                    let mem_mb = parse_mem_to_mb(mem_str);
                    if let Some(c) = containers.iter_mut().find(|c| c.name == name) {
                        c.cpu_pct = cpu;
                        c.mem_mb = mem_mb;
                    }
                }
            }
        }
    }

    containers
}

fn parse_mem_to_mb(s: &str) -> f64 {
    let s = s.trim();
    if let Some(v) = s.strip_suffix("GiB") {
        v.trim().parse::<f64>().unwrap_or(0.0) * 1024.0
    } else if let Some(v) = s.strip_suffix("MiB") {
        v.trim().parse::<f64>().unwrap_or(0.0)
    } else if let Some(v) = s.strip_suffix("KiB") {
        v.trim().parse::<f64>().unwrap_or(0.0) / 1024.0
    } else if let Some(v) = s.strip_suffix("B") {
        v.trim().parse::<f64>().unwrap_or(0.0) / 1_048_576.0
    } else {
        s.parse::<f64>().unwrap_or(0.0)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SystemMetrics {
    pub total_memory_gb: f64,
    pub available_memory_gb: f64,
    pub load_1: f64,
    pub load_5: f64,
    pub load_15: f64,
    pub cpu_usage_pct: f64,
    pub cpu_cores: u32,
    pub uptime_seconds: u64,
    pub disks: Vec<DiskPartition>,
    pub network: Vec<NetworkInterface>,
    pub docker: Vec<DockerContainer>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DiskPartition {
    pub device: String,
    pub mount: String,
    pub total_gb: f64,
    pub used_gb: f64,
    pub avail_gb: f64,
    pub use_pct: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DockerContainer {
    pub name: String,
    pub image: String,
    pub status: String,
    pub state: String,
    pub ports: String,
    pub cpu_pct: f64,
    pub mem_mb: f64,
}

// ── Process Monitoring ───────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub user: String,
    pub state: String,
    pub cpu_pct: f64,
    pub mem_mb: f64,
    pub mem_pct: f64,
    pub threads: u32,
    pub command: String,
}

/// Read top processes by CPU usage from /proc.
/// Falls back to `ps aux` if /proc parsing fails.
pub async fn get_top_processes(limit: u32) -> Result<Vec<ProcessInfo>, String> {
    use std::fs;

    let meminfo = fs::read_to_string("/proc/meminfo").map_err(|e| e.to_string())?;
    let total_mem_kb: u64 = meminfo
        .lines()
        .find(|l| l.starts_with("MemTotal:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);

    let uptime_s: f64 = fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next().and_then(|v| v.parse().ok()))
        .unwrap_or(1.0);

    let hertz = 100u64; // USER_HZ (getconf CLK_TCK == 100 on Linux x86)

    let mut procs: Vec<ProcessInfo> = Vec::new();

    let Ok(proc_dir) = fs::read_dir("/proc") else {
        return Err("Cannot read /proc".into());
    };

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let Ok(pid) = name_str.parse::<u32>() else {
            continue;
        };

        // stat: pid (comm) state ... utime stime ... rss ...
        let stat_path = format!("/proc/{}/stat", pid);
        let Ok(stat) = fs::read_to_string(&stat_path) else {
            continue;
        };

        // The comm field can contain spaces and is surrounded by parens
        let comm_end = stat.rfind(')').unwrap_or(0);
        let comm_start = stat.find('(').unwrap_or(0) + 1;
        let proc_name = stat[comm_start..comm_end].to_string();

        let after_comm = &stat[comm_end + 2..]; // skip ') '
        let fields: Vec<&str> = after_comm.split_whitespace().collect();
        // fields[0]=state, [11]=utime, [12]=stime, [17]=num_threads, [21]=starttime
        // (indices are 0-based after state)
        let state = fields.first().unwrap_or(&"?").to_string();
        let utime: u64 = fields.get(11).and_then(|s| s.parse().ok()).unwrap_or(0);
        let stime: u64 = fields.get(12).and_then(|s| s.parse().ok()).unwrap_or(0);
        let threads: u32 = fields.get(17).and_then(|s| s.parse().ok()).unwrap_or(1);
        let starttime: u64 = fields.get(19).and_then(|s| s.parse().ok()).unwrap_or(0);

        // RSS from /proc/pid/statm (in pages)
        let statm_path = format!("/proc/{}/statm", pid);
        let rss_pages: u64 = fs::read_to_string(&statm_path)
            .ok()
            .and_then(|s| s.split_whitespace().nth(1).and_then(|v| v.parse().ok()))
            .unwrap_or(0);
        let rss_kb = rss_pages * 4; // PAGE_SIZE = 4096 bytes = 4 KB
        let mem_mb = rss_kb as f64 / 1024.0;
        let mem_pct = (rss_kb as f64 / total_mem_kb as f64) * 100.0;

        // CPU % = (utime + stime) / (uptime - starttime/hertz) * 100
        let total_ticks = utime + stime;
        let proc_uptime = uptime_s - (starttime as f64 / hertz as f64);
        let cpu_pct = if proc_uptime > 0.0 {
            (total_ticks as f64 / hertz as f64 / proc_uptime * 100.0).clamp(0.0, 100.0 * 128.0)
        } else {
            0.0
        };

        // Owner from /proc/pid/status
        let uid: u32 = fs::read_to_string(format!("/proc/{}/status", pid))
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("Uid:"))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|v| v.parse().ok())
            })
            .unwrap_or(0);

        // Resolve UID → username from /etc/passwd (simple lookup)
        let user = resolve_uid(uid);

        // Cmdline
        let command = fs::read_to_string(format!("/proc/{}/cmdline", pid))
            .ok()
            .map(|s| s.replace('\0', " ").trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| format!("[{}]", proc_name));

        procs.push(ProcessInfo {
            pid,
            name: proc_name,
            user,
            state,
            cpu_pct,
            mem_mb,
            mem_pct,
            threads,
            command,
        });
    }

    // Sort by CPU descending, then mem descending
    procs.sort_by(|a, b| {
        b.cpu_pct
            .partial_cmp(&a.cpu_pct)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(
                b.mem_mb
                    .partial_cmp(&a.mem_mb)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
    });

    procs.truncate(limit as usize);
    Ok(procs)
}

/// Resolve a UID to a username by reading /etc/passwd.
fn resolve_uid(uid: u32) -> String {
    use std::fs;
    let passwd = fs::read_to_string("/etc/passwd").unwrap_or_default();
    for line in passwd.lines() {
        let parts: Vec<&str> = line.splitn(4, ':').collect();
        if parts.len() >= 3 && parts[2].parse::<u32>().ok() == Some(uid) {
            return parts[0].to_string();
        }
    }
    uid.to_string()
}

// ── Disk I/O Snapshot ────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DiskIoSnapshot {
    pub timestamp_ms: u64,
    pub devices: Vec<DiskIoDevice>,
}

#[derive(Debug, Clone)]
pub struct DiskIoDevice {
    pub name: String,
    pub reads_completed: u64,
    pub sectors_read: u64,
    pub writes_completed: u64,
    pub sectors_written: u64,
    pub read_bps: f64,
    pub write_bps: f64,
}

/// Read /proc/diskstats once.
fn read_diskstats() -> Vec<(String, u64, u64, u64, u64)> {
    use std::fs;
    let Ok(content) = fs::read_to_string("/proc/diskstats") else {
        return vec![];
    };
    content
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 14 {
                return None;
            }
            let name = parts[2].to_string();
            // Skip loop, ram devices
            if name.starts_with("loop") || name.starts_with("ram") {
                return None;
            }
            let reads_completed: u64 = parts[3].parse().ok()?;
            let sectors_read: u64 = parts[5].parse().ok()?;
            let writes_completed: u64 = parts[7].parse().ok()?;
            let sectors_written: u64 = parts[9].parse().ok()?;
            Some((
                name,
                reads_completed,
                sectors_read,
                writes_completed,
                sectors_written,
            ))
        })
        .collect()
}

/// Sample disk I/O twice over 500ms and return byte rates.
pub async fn get_disk_io_snapshot() -> Result<DiskIoSnapshot, String> {
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::time::{sleep, Duration};

    let s1 = read_diskstats();
    sleep(Duration::from_millis(500)).await;
    let s2 = read_diskstats();

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let sector_size: f64 = 512.0;
    let interval: f64 = 0.5; // seconds

    let devices = s2
        .into_iter()
        .filter_map(|(name, rc2, sr2, wc2, sw2)| {
            let found = s1.iter().find(|(n, ..)| n == &name)?;
            let (_rc1, sr1, _wc1, sw1) = (found.1, found.2, found.3, found.4);
            let read_bps = ((sr2.saturating_sub(sr1)) as f64 * sector_size) / interval;
            let write_bps = ((sw2.saturating_sub(sw1)) as f64 * sector_size) / interval;
            Some(DiskIoDevice {
                name,
                reads_completed: rc2,
                sectors_read: sr2,
                writes_completed: wc2,
                sectors_written: sw2,
                read_bps,
                write_bps,
            })
        })
        .collect();

    Ok(DiskIoSnapshot {
        timestamp_ms: ts,
        devices,
    })
}

// ── Network Rate Snapshot ────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct NetworkRateSnapshot {
    pub timestamp_ms: u64,
    pub interfaces: Vec<NetworkRateIface>,
}

#[derive(Debug, Clone)]
pub struct NetworkRateIface {
    pub name: String,
    pub rx_bps: f64,
    pub tx_bps: f64,
}

fn read_net_dev() -> Vec<(String, u64, u64)> {
    use std::fs;
    let Ok(content) = fs::read_to_string("/proc/net/dev") else {
        return vec![];
    };
    content
        .lines()
        .skip(2)
        .filter_map(|line| {
            let (iface, rest) = line.split_once(':')?;
            let iface = iface.trim().to_string();
            if iface == "lo" {
                return None;
            }
            let nums: Vec<u64> = rest
                .split_whitespace()
                .filter_map(|s| s.parse().ok())
                .collect();
            if nums.len() < 9 {
                return None;
            }
            Some((iface, nums[0], nums[8]))
        })
        .collect()
}

/// Sample /proc/net/dev twice over 500ms and return byte rates per interface.
pub async fn get_network_rate_snapshot() -> Result<NetworkRateSnapshot, String> {
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::time::{sleep, Duration};

    let s1 = read_net_dev();
    sleep(Duration::from_millis(500)).await;
    let s2 = read_net_dev();

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let interval: f64 = 0.5;

    let interfaces = s2
        .into_iter()
        .filter_map(|(name, rx2, tx2)| {
            let found = s1.iter().find(|(n, ..)| n == &name)?;
            let (rx1, tx1) = (found.1, found.2);
            Some(NetworkRateIface {
                name,
                rx_bps: rx2.saturating_sub(rx1) as f64 / interval,
                tx_bps: tx2.saturating_sub(tx1) as f64 / interval,
            })
        })
        .collect();

    Ok(NetworkRateSnapshot {
        timestamp_ms: ts,
        interfaces,
    })
}
