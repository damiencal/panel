/// Monitoring and admin statistics server functions.
use crate::models::auth::AuditLogEntry;
use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

/// System metrics (CPU load, memory, disk, network, docker) — duplicated here for cross-target visibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskPartition {
    pub device: String,
    pub mount: String,
    pub total_gb: f64,
    pub used_gb: f64,
    pub avail_gb: f64,
    pub use_pct: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerContainer {
    pub name: String,
    pub image: String,
    pub status: String,
    pub state: String,
    pub ports: String,
    pub cpu_pct: f64,
    pub mem_mb: f64,
}

/// Admin dashboard aggregate stats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminStats {
    pub total_users: i64,
    pub total_resellers: i64,
    pub total_clients: i64,
    pub total_sites: i64,
    pub total_databases: i64,
}

/// Client dashboard summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientDashboardData {
    pub sites_count: i64,
    pub databases_count: i64,
    pub email_domains_count: i64,
    pub open_tickets: i64,
}

/// Information about a single heartbeat beat task (most recent run).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeatInfo {
    pub last_ran_at: chrono::DateTime<chrono::Utc>,
    pub status: crate::models::task::TaskStatus,
    pub log_output: Option<String>,
}

/// Admin-visible summary of the latest heartbeat beat outcomes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatStatus {
    pub pulse: Option<BeatInfo>,
    pub maintenance: Option<BeatInfo>,
    pub quotas: Option<BeatInfo>,
}

#[cfg(feature = "server")]
async fn run_command_output_with_timeout(
    cmd: &str,
    args: &[&str],
    timeout_secs: u64,
) -> Result<std::process::Output, ServerFnError> {
    use tokio::process::Command;
    use tokio::time::{timeout, Duration};

    if !crate::services::shell::is_allowed(cmd) {
        return Err(ServerFnError::new(format!(
            "{cmd} is not in the command allowlist"
        )));
    }

    timeout(
        Duration::from_secs(timeout_secs),
        Command::new(cmd).args(args).output(),
    )
    .await
    .map_err(|_| ServerFnError::new(format!("{cmd} timed out after {timeout_secs} s")))?
    .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Get admin dashboard statistics.
#[server]
pub async fn server_get_admin_stats() -> Result<AdminStats, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    let users = crate::db::users::list_all(pool)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let total_users = users.len() as i64;
    let total_resellers = users
        .iter()
        .filter(|u| u.role == crate::models::user::Role::Reseller)
        .count() as i64;
    let total_clients = users
        .iter()
        .filter(|u| u.role == crate::models::user::Role::Client)
        .count() as i64;

    let sites = crate::db::sites::list_all(pool)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let databases = crate::db::databases::list_all(pool)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(AdminStats {
        total_users,
        total_resellers,
        total_clients,
        total_sites: sites.len() as i64,
        total_databases: databases.len() as i64,
    })
}

/// Get client dashboard data.
#[server]
pub async fn server_get_client_dashboard() -> Result<ClientDashboardData, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    let sites = crate::db::sites::list_for_owner(pool, claims.sub)
        .await
        .unwrap_or_default();
    let databases = crate::db::databases::list_for_owner(pool, claims.sub)
        .await
        .unwrap_or_default();
    let email_domains = crate::db::email::list_domains(pool, claims.sub)
        .await
        .unwrap_or_default();
    let tickets = crate::db::tickets::list_tickets(pool, claims.sub)
        .await
        .unwrap_or_default();

    let open_tickets = tickets
        .iter()
        .filter(|t| t.status != crate::models::ticket::TicketStatus::Closed)
        .count() as i64;

    Ok(ClientDashboardData {
        sites_count: sites.len() as i64,
        databases_count: databases.len() as i64,
        email_domains_count: email_domains.len() as i64,
        open_tickets,
    })
}

/// Get recent audit log entries (admin only).
#[server]
pub async fn server_get_audit_log(limit: i64) -> Result<Vec<AuditLogEntry>, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;

    if !(1..=1000).contains(&limit) {
        return Err(ServerFnError::new("limit must be between 1 and 1000"));
    }

    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    // Use raw query since audit functions return SqliteRow
    let rows = sqlx::query_as::<_, AuditLogEntryRow>(
        "SELECT id, user_id, action, target_type, target_id, target_name, \
         description, status, error_message, ip_address, impersonation_by, created_at \
         FROM audit_logs ORDER BY created_at DESC LIMIT ?",
    )
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(rows
        .into_iter()
        .map(|r| AuditLogEntry {
            id: r.id,
            user_id: r.user_id,
            action: r.action,
            target_type: r.target_type,
            target_id: r.target_id,
            target_name: r.target_name,
            description: r.description,
            status: r.status,
            error_message: r.error_message,
            ip_address: r.ip_address,
            impersonation_by: r.impersonation_by,
            created_at: r.created_at.to_rfc3339(),
        })
        .collect())
}

/// Internal row type for SQLx deserialization.
#[cfg(feature = "server")]
#[derive(sqlx::FromRow)]
struct AuditLogEntryRow {
    id: i64,
    user_id: i64,
    action: String,
    target_type: Option<String>,
    target_id: Option<i64>,
    target_name: Option<String>,
    description: Option<String>,
    status: String,
    error_message: Option<String>,
    ip_address: Option<String>,
    impersonation_by: Option<i64>,
    created_at: chrono::DateTime<chrono::Utc>,
}

/// Get system metrics (CPU load, memory, disk, network, docker).
#[server]
pub async fn server_get_system_metrics() -> Result<SystemMetrics, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    let m = crate::services::system::get_system_metrics()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(SystemMetrics {
        total_memory_gb: m.total_memory_gb,
        available_memory_gb: m.available_memory_gb,
        load_1: m.load_1,
        load_5: m.load_5,
        load_15: m.load_15,
        cpu_usage_pct: m.cpu_usage_pct,
        cpu_cores: m.cpu_cores,
        uptime_seconds: m.uptime_seconds,
        disks: m
            .disks
            .into_iter()
            .map(|d| DiskPartition {
                device: d.device,
                mount: d.mount,
                total_gb: d.total_gb,
                used_gb: d.used_gb,
                avail_gb: d.avail_gb,
                use_pct: d.use_pct,
            })
            .collect(),
        network: m
            .network
            .into_iter()
            .map(|n| NetworkInterface {
                name: n.name,
                rx_bytes: n.rx_bytes,
                tx_bytes: n.tx_bytes,
                rx_packets: n.rx_packets,
                tx_packets: n.tx_packets,
                rx_errors: n.rx_errors,
                tx_errors: n.tx_errors,
            })
            .collect(),
        docker: m
            .docker
            .into_iter()
            .map(|d| DockerContainer {
                name: d.name,
                image: d.image,
                status: d.status,
                state: d.state,
                ports: d.ports,
                cpu_pct: d.cpu_pct,
                mem_mb: d.mem_mb,
            })
            .collect(),
    })
}

/// Static server/OS information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub hostname: String,
    pub os_name: String,
    pub kernel_version: String,
    pub architecture: String,
    pub cpu_model: String,
    pub cpu_cores: u32,
    pub cpu_threads: u32,
    pub total_memory_gb: f64,
    pub total_swap_gb: f64,
    pub uptime_seconds: u64,
    pub updates_available: u32,
    pub security_updates: u32,
    pub last_update_check: Option<String>,
}

/// Get static server information (hostname, OS, CPU, RAM, pending updates).
#[server]
pub async fn server_get_server_info() -> Result<ServerInfo, ServerFnError> {
    use super::helpers::*;
    use std::fs;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    // hostname
    let hostname = fs::read_to_string("/proc/sys/kernel/hostname")
        .unwrap_or_default()
        .trim()
        .to_string();

    // kernel version
    let kernel_version = fs::read_to_string("/proc/version")
        .unwrap_or_default()
        .split_whitespace()
        .nth(2)
        .unwrap_or("unknown")
        .to_string();

    // architecture
    let arch_out = std::env::consts::ARCH.to_string();

    // OS name from /etc/os-release
    let os_name = fs::read_to_string("/etc/os-release")
        .unwrap_or_default()
        .lines()
        .find(|l| l.starts_with("PRETTY_NAME="))
        .map(|l| {
            l.trim_start_matches("PRETTY_NAME=")
                .trim_matches('"')
                .to_string()
        })
        .unwrap_or_else(|| "Linux".to_string());

    // CPU info from /proc/cpuinfo
    let cpuinfo = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let cpu_threads = cpuinfo
        .lines()
        .filter(|l| l.starts_with("processor"))
        .count() as u32;
    let cpu_cores = cpuinfo
        .lines()
        .find(|l| l.starts_with("cpu cores"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(cpu_threads);
    let cpu_model = cpuinfo
        .lines()
        .find(|l| l.starts_with("model name"))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "Unknown CPU".to_string());

    // Memory/swap from /proc/meminfo
    let meminfo = fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let mut total_mem_kb = 0u64;
    let mut total_swap_kb = 0u64;
    for line in meminfo.lines() {
        if let Some(v) = line.strip_prefix("MemTotal:") {
            total_mem_kb = v
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
        }
        if let Some(v) = line.strip_prefix("SwapTotal:") {
            total_swap_kb = v
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
        }
    }

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

    // Pending updates (apt-get --dry-run upgrade)
    let apt_out = run_command_output_with_timeout("apt-get", &["-s", "upgrade"], 120)
        .await
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    let updates_available = apt_out.lines().filter(|l| l.starts_with("Inst ")).count() as u32;
    let security_updates = apt_out
        .lines()
        .filter(|l| l.starts_with("Inst ") && l.contains("-security"))
        .count() as u32;

    // Last apt update timestamp
    let last_update_check = fs::metadata("/var/lib/apt/periodic/update-success-stamp")
        .ok()
        .and_then(|m| m.modified().ok())
        .map(|t| {
            let dt: chrono::DateTime<chrono::Utc> = t.into();
            dt.format("%Y-%m-%d %H:%M UTC").to_string()
        });

    Ok(ServerInfo {
        hostname,
        os_name,
        kernel_version,
        architecture: arch_out,
        cpu_model,
        cpu_cores,
        cpu_threads,
        total_memory_gb: total_mem_kb as f64 / 1024.0 / 1024.0,
        total_swap_gb: total_swap_kb as f64 / 1024.0 / 1024.0,
        uptime_seconds,
        updates_available,
        security_updates,
        last_update_check,
    })
}

// ── Process Monitoring ───────────────────────────────────────────

/// Information about a running process.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Get the top processes sorted by CPU usage.
#[server]
pub async fn server_get_top_processes(limit: u32) -> Result<Vec<ProcessInfo>, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    if limit > 500 {
        return Err(ServerFnError::new("limit must be <= 500"));
    }

    let procs = crate::services::system::get_top_processes(limit)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(procs
        .into_iter()
        .map(|p| ProcessInfo {
            pid: p.pid,
            name: p.name,
            user: p.user,
            state: p.state,
            cpu_pct: p.cpu_pct,
            mem_mb: p.mem_mb,
            mem_pct: p.mem_pct,
            threads: p.threads,
            command: p.command,
        })
        .collect())
}

/// Send SIGTERM (or SIGKILL with force=true) to a process by PID.
/// Only admins may call this; init (PID 1) and the panel process itself are protected.
#[server]
pub async fn server_kill_process(pid: u32, force: bool) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    // Guard: never kill PID 1 (init/systemd) or PID 0
    if pid <= 1 {
        return Err(ServerFnError::new("Cannot kill system process (PID <= 1)"));
    }

    // Guard: never kill our own process
    let own_pid = std::process::id();
    if pid == own_pid {
        return Err(ServerFnError::new("Cannot kill the panel process itself"));
    }

    let signal = if force { "9" } else { "15" };
    crate::services::shell::exec("kill", &[&format!("-{signal}"), &pid.to_string()])
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    let _ = audit_log(
        claims.sub,
        &format!("kill_process_{}", if force { "kill" } else { "term" }),
        Some("process"),
        Some(pid as i64),
        Some(&format!("PID {}", pid)),
        "success",
        None,
    )
    .await;

    Ok(())
}

// ── Disk I/O Statistics ──────────────────────────────────────────

/// A single disk I/O sample point with timestamp.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskIoSnapshot {
    pub timestamp_ms: u64,
    pub devices: Vec<DiskIoDevice>,
}

/// Per-device disk I/O counters from /proc/diskstats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskIoDevice {
    pub name: String,
    pub reads_completed: u64,
    pub sectors_read: u64,
    pub writes_completed: u64,
    pub sectors_written: u64,
    /// Derived bytes read per second (calculated from two snapshots on the server).
    pub read_bps: f64,
    /// Derived bytes written per second.
    pub write_bps: f64,
}

/// Get a disk I/O rate snapshot (sampled over 500 ms internally).
#[server]
pub async fn server_get_disk_io() -> Result<DiskIoSnapshot, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    let snap = crate::services::system::get_disk_io_snapshot()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(DiskIoSnapshot {
        timestamp_ms: snap.timestamp_ms,
        devices: snap
            .devices
            .into_iter()
            .map(|d| DiskIoDevice {
                name: d.name,
                reads_completed: d.reads_completed,
                sectors_read: d.sectors_read,
                writes_completed: d.writes_completed,
                sectors_written: d.sectors_written,
                read_bps: d.read_bps,
                write_bps: d.write_bps,
            })
            .collect(),
    })
}

/// Get a compact network traffic rate snapshot (bytes/sec per interface, sampled over 500ms).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkRateSnapshot {
    pub timestamp_ms: u64,
    pub interfaces: Vec<NetworkRateIface>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkRateIface {
    pub name: String,
    pub rx_bps: f64,
    pub tx_bps: f64,
}

/// Get per-interface traffic rates sampled over 500 ms.
#[server]
pub async fn server_get_network_rates() -> Result<NetworkRateSnapshot, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    let snap = crate::services::system::get_network_rate_snapshot()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(NetworkRateSnapshot {
        timestamp_ms: snap.timestamp_ms,
        interfaces: snap
            .interfaces
            .into_iter()
            .map(|i| NetworkRateIface {
                name: i.name,
                rx_bps: i.rx_bps,
                tx_bps: i.tx_bps,
            })
            .collect(),
    })
}

// ── Panel Version / Update ────────────────────────────────────────

/// Information about the current and latest panel version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanelVersionInfo {
    /// The version currently running (from `CARGO_PKG_VERSION`).
    pub current: String,
    /// The latest version published on GitHub Releases.
    pub latest: String,
    /// Whether `latest` is newer than `current`.
    pub update_available: bool,
    /// HTML URL of the latest GitHub release page.
    pub release_url: String,
    /// Release notes body (markdown) of the latest release.
    pub release_notes: String,
}

/// Result returned after a panel binary self-update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanelUpdateResult {
    pub success: bool,
    pub message: String,
}

// ── OS Update ────────────────────────────────────────────────────

/// Result of an OS package update run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsUpdateResult {
    /// Number of packages upgraded.
    pub packages_upgraded: u32,
    /// Number of new packages installed.
    pub packages_installed: u32,
    /// Number of packages removed.
    pub packages_removed: u32,
    /// Truncated tail of the apt output (last 4 KB).
    pub output_tail: String,
}

#[cfg(feature = "server")]
fn is_apt_lock_error(stderr: &str) -> bool {
    let lowered = stderr.to_ascii_lowercase();
    (lowered.contains("unable to lock directory") || lowered.contains("could not get lock"))
        && (lowered.contains("/var/lib/apt/lists") || lowered.contains("/var/lib/dpkg/lock"))
}

#[cfg(feature = "server")]
fn needs_privileged_package_manager() -> bool {
    unsafe { nix::libc::geteuid() != 0 }
}

#[cfg(feature = "server")]
async fn run_apt_with_retries(
    args: &[&str],
    label: &str,
    timeout_secs: u64,
    max_attempts: u32,
) -> Result<std::process::Output, ServerFnError> {
    use tokio::process::Command;
    use tokio::time::{sleep, timeout, Duration};

    if !crate::services::shell::is_allowed("apt-get") {
        return Err(ServerFnError::new(
            "apt-get is not in the command allowlist".to_string(),
        ));
    }

    let use_sudo = needs_privileged_package_manager();
    if use_sudo && !crate::services::shell::is_allowed("sudo") {
        return Err(ServerFnError::new(
            "sudo is not in the command allowlist".to_string(),
        ));
    }

    for attempt in 1..=max_attempts {
        let mut command = if use_sudo {
            let mut cmd = Command::new("sudo");
            cmd.arg("-n").arg("apt-get").args(args);
            cmd
        } else {
            let mut cmd = Command::new("apt-get");
            cmd.args(args);
            cmd
        };

        let out = timeout(
            Duration::from_secs(timeout_secs),
            command.env("DEBIAN_FRONTEND", "noninteractive").output(),
        )
        .await
        .map_err(|_| ServerFnError::new(format!("{} timed out after {} s", label, timeout_secs)))?
        .map_err(|e| ServerFnError::new(e.to_string()))?;

        if out.status.success() {
            return Ok(out);
        }

        let stderr = String::from_utf8_lossy(&out.stderr);
        if attempt < max_attempts && is_apt_lock_error(&stderr) {
            let backoff_secs = 10 * u64::from(attempt);
            tracing::warn!(
                label,
                attempt,
                max_attempts,
                backoff_secs,
                "apt lock detected; retrying"
            );
            sleep(Duration::from_secs(backoff_secs)).await;
            continue;
        }

        return Ok(out);
    }

    Err(ServerFnError::new(format!(
        "{} failed after {} attempts",
        label, max_attempts
    )))
}

/// Trigger `apt-get update && apt-get upgrade -y` on the host (admin only).
///
/// The update is run with a 10-minute timeout.  The full upgrade output is
/// captured and the last 4 KB is returned so the UI can display progress.
#[server]
pub async fn server_trigger_os_update() -> Result<OsUpdateResult, ServerFnError> {
    use super::helpers::*;
    use tokio::process::Command;
    use tokio::time::{timeout, Duration};

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    // Step 1: Reconfigure any partially-configured packages before updating.
    // Note: we intentionally do NOT delete apt lock files — modern apt/dpkg
    // manages stale locks internally. Forcibly removing them while another
    // process holds them on Linux would not evict the holder (the fd stays
    // open) and could corrupt the dpkg database.
    if !crate::services::shell::is_allowed("dpkg") {
        return Err(ServerFnError::new(
            "dpkg is not in the command allowlist".to_string(),
        ));
    }
    let use_sudo = needs_privileged_package_manager();
    if use_sudo && !crate::services::shell::is_allowed("sudo") {
        return Err(ServerFnError::new(
            "sudo is not in the command allowlist".to_string(),
        ));
    }
    let mut dpkg_command = if use_sudo {
        let mut cmd = Command::new("sudo");
        cmd.arg("-n").arg("dpkg").args(["--configure", "-a"]);
        cmd
    } else {
        let mut cmd = Command::new("dpkg");
        cmd.args(["--configure", "-a"]);
        cmd
    };
    let _ = timeout(
        Duration::from_secs(60),
        dpkg_command
            .env("DEBIAN_FRONTEND", "noninteractive")
            .output(),
    )
    .await;

    // Step 2: refresh package lists
    let update_out = run_apt_with_retries(&["-y", "update"], "apt-get update", 120, 4).await?;

    if !update_out.status.success() {
        let stderr = String::from_utf8_lossy(&update_out.stderr).to_string();
        let _ = audit_log(
            claims.sub,
            "os_update",
            Some("system"),
            None,
            Some("apt-get update"),
            "Failure",
            Some(&stderr),
        )
        .await;
        return Err(ServerFnError::new(format!(
            "apt-get update failed: {}",
            stderr.lines().last().unwrap_or("unknown error")
        )));
    }

    // Step 3: perform the upgrade
    let upgrade_out = run_apt_with_retries(&["-y", "upgrade"], "apt-get upgrade", 600, 4).await?;

    let stdout = String::from_utf8_lossy(&upgrade_out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&upgrade_out.stderr).to_string();
    let combined = format!("{}{}", stdout, stderr);

    if !upgrade_out.status.success() {
        let _ = audit_log(
            claims.sub,
            "os_update",
            Some("system"),
            None,
            Some("apt-get upgrade"),
            "Failure",
            Some(&stderr),
        )
        .await;
        return Err(ServerFnError::new(format!(
            "apt-get upgrade failed: {}",
            stderr.lines().last().unwrap_or("unknown error")
        )));
    }

    // Parse summary line: "X upgraded, Y newly installed, Z to remove …"
    let mut packages_upgraded = 0u32;
    let mut packages_installed = 0u32;
    let mut packages_removed = 0u32;
    for line in stdout.lines() {
        if line.contains("upgraded,") && line.contains("newly installed") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            // Format: "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded."
            packages_upgraded = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
            packages_installed = parts.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
            packages_removed = parts.get(6).and_then(|s| s.parse().ok()).unwrap_or(0);
            break;
        }
    }

    // Return the last 4 KB of combined output
    let output_tail = if combined.len() > 4096 {
        combined[combined.len() - 4096..].to_string()
    } else {
        combined
    };

    let _ = audit_log(
        claims.sub,
        "os_update",
        Some("system"),
        None,
        Some("apt-get upgrade"),
        "Success",
        None,
    )
    .await;

    Ok(OsUpdateResult {
        packages_upgraded,
        packages_installed,
        packages_removed,
        output_tail,
    })
}

// ── Panel self-update ─────────────────────────────────────────────────────────

/// Compare two semver strings (e.g. "0.1.0" vs "0.2.0").
/// Returns true when `candidate` is strictly newer than `current`.
/// Ignores pre-release / build metadata — only major.minor.patch matters.
#[cfg(feature = "server")]
fn semver_newer(current: &str, candidate: &str) -> bool {
    fn parse(v: &str) -> (u64, u64, u64) {
        let v = v.trim_start_matches('v');
        let mut parts = v.splitn(3, '.').map(|p| {
            p.split('-')
                .next()
                .unwrap_or("0")
                .parse::<u64>()
                .unwrap_or(0)
        });
        (
            parts.next().unwrap_or(0),
            parts.next().unwrap_or(0),
            parts.next().unwrap_or(0),
        )
    }
    parse(candidate) > parse(current)
}

/// Check whether a newer version of the panel is available on GitHub Releases.
///
/// Queries `https://api.github.com/repos/damiencal/panel/releases/latest` and
/// compares the published `tag_name` against the compiled-in `CARGO_PKG_VERSION`.
/// If the network request fails for any reason the function returns successfully
/// with `update_available = false` so the UI never shows a false alarm.
#[server]
pub async fn server_check_panel_version() -> Result<PanelVersionInfo, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    let current = env!("CARGO_PKG_VERSION").to_string();

    let no_update = PanelVersionInfo {
        latest: current.clone(),
        update_available: false,
        release_url: String::new(),
        release_notes: String::new(),
        current: current.clone(),
    };

    #[derive(serde::Deserialize)]
    struct GhRelease {
        tag_name: String,
        html_url: String,
        body: Option<String>,
    }

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(_) => return Ok(no_update),
    };

    let resp = match client
        .get("https://api.github.com/repos/damiencal/panel/releases/latest")
        .header(reqwest::header::USER_AGENT, format!("panel/{current}"))
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return Ok(no_update),
    };

    // Non-2xx (e.g. 404 when there are no releases yet) → no update
    if !resp.status().is_success() {
        return Ok(no_update);
    }

    let release: GhRelease = match resp.json().await {
        Ok(r) => r,
        Err(_) => return Ok(no_update),
    };

    let latest = release.tag_name.trim_start_matches('v').to_string();
    let update_available = semver_newer(&current, &latest);

    Ok(PanelVersionInfo {
        current,
        latest,
        update_available,
        release_url: release.html_url,
        release_notes: release.body.unwrap_or_default(),
    })
}

/// Download, verify, and install the latest panel binary from GitHub Releases.
///
/// Steps:
/// 1. Detect host architecture.
/// 2. Fetch the latest release metadata from GitHub API.
/// 3. Download the release archive and its `.sha256` checksum file.
/// 4. Verify the SHA-256 digest before touching the filesystem.
/// 5. Extract the binary and replace `/opt/panel/panel` atomically.
/// 6. Return success to the client, then fire a systemd restart (background).
#[server]
pub async fn server_trigger_panel_update() -> Result<PanelUpdateResult, ServerFnError> {
    use super::helpers::*;
    use sha2::{Digest, Sha256};
    use std::io::Write;
    use tokio::process::Command;
    use tokio::time::{timeout, Duration};

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    // ── Step 1: determine archive name from host architecture ──────────────
    let archive_name = match std::env::consts::ARCH {
        "x86_64" => "panel-x86_64-linux.tar.gz",
        "aarch64" => "panel-aarch64-linux.tar.gz",
        arch => {
            return Err(ServerFnError::new(format!(
                "Unsupported architecture: {arch}. Please update manually."
            )));
        }
    };

    // ── Step 2: resolve latest release tag from GitHub API ────────────────
    #[derive(serde::Deserialize)]
    struct GhRelease {
        tag_name: String,
        html_url: String,
    }

    let current = env!("CARGO_PKG_VERSION").to_string();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| ServerFnError::new(format!("Failed to build HTTP client: {e}")))?;

    let release: GhRelease = client
        .get("https://api.github.com/repos/damiencal/panel/releases/latest")
        .header(reqwest::header::USER_AGENT, format!("panel/{current}"))
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| ServerFnError::new(format!("GitHub API request failed: {e}")))?
        .json()
        .await
        .map_err(|e| ServerFnError::new(format!("Failed to parse GitHub API response: {e}")))?;

    let tag = &release.tag_name;

    // Validate tag_name before interpolating it into a download URL.
    // Only allow semver-style tags (e.g. "v1.2.3" or "1.2.3-rc1") to
    // prevent path traversal or URL manipulation via a compromised API response.
    {
        let tag_re = regex::Regex::new(r"^v?\d+\.\d+\.\d+(-[a-zA-Z0-9._-]+)?(\+[a-zA-Z0-9._-]+)?$")
            .expect("static regex");
        if !tag_re.is_match(tag) {
            return Err(ServerFnError::new(format!(
                "GitHub release tag has unexpected format: {tag:?}. \
                 Expected semver like v1.2.3. Aborting update."
            )));
        }
    }

    let base_url = format!("https://github.com/damiencal/panel/releases/download/{tag}");

    // ── Step 3: download archive and checksum ─────────────────────────────
    let tmp_dir = tempfile::Builder::new()
        .prefix("panel-update-")
        .tempdir()
        .map_err(|e| ServerFnError::new(format!("Failed to create temp dir: {e}")))?;

    let archive_path = tmp_dir.path().join(archive_name);

    // Helper: download a URL to bytes with a 5‑minute timeout.
    async fn download(client: &reqwest::Client, url: &str) -> Result<Vec<u8>, String> {
        let bytes = client
            .get(url)
            .send()
            .await
            .map_err(|e| format!("Download request failed for {url}: {e}"))?
            .error_for_status()
            .map_err(|e| format!("HTTP error for {url}: {e}"))?
            .bytes()
            .await
            .map_err(|e| format!("Failed to read response body from {url}: {e}"))?;
        Ok(bytes.to_vec())
    }

    let archive_url = format!("{base_url}/{archive_name}");
    let sha256_url = format!("{base_url}/{archive_name}.sha256");

    let archive_bytes = timeout(Duration::from_secs(300), download(&client, &archive_url))
        .await
        .map_err(|_| ServerFnError::new(format!("Download timed out: {archive_url}")))?
        .map_err(ServerFnError::new)?;
    let sha256_bytes = timeout(Duration::from_secs(30), download(&client, &sha256_url))
        .await
        .map_err(|_| ServerFnError::new(format!("Download timed out: {sha256_url}")))?
        .map_err(ServerFnError::new)?;

    // ── Step 4: verify SHA-256 checksum ───────────────────────────────────
    let expected_hex = std::str::from_utf8(&sha256_bytes)
        .map_err(|e| ServerFnError::new(format!("Invalid checksum file encoding: {e}")))?
        .split_whitespace()
        .next()
        .ok_or_else(|| ServerFnError::new("Checksum file is empty".to_string()))?
        .to_lowercase();

    let mut hasher = Sha256::new();
    hasher.update(&archive_bytes);
    let actual_hex = format!("{:x}", hasher.finalize());

    if expected_hex != actual_hex {
        return Err(ServerFnError::new(format!(
            "SHA-256 checksum mismatch — download may be corrupted.\n\
             Expected: {expected_hex}\n\
             Got:      {actual_hex}"
        )));
    }

    // Write verified archive to temp file for extraction
    {
        let mut f = std::fs::File::create(&archive_path)
            .map_err(|e| ServerFnError::new(format!("Failed to write archive: {e}")))?;
        f.write_all(&archive_bytes)
            .map_err(|e| ServerFnError::new(format!("Failed to write archive bytes: {e}")))?;
    }

    // ── Step 5: extract binary ────────────────────────────────────────────
    let extract_dir = tmp_dir.path().join("extract");
    std::fs::create_dir_all(&extract_dir)
        .map_err(|e| ServerFnError::new(format!("Failed to create extract dir: {e}")))?;

    let archive_path_str = archive_path
        .to_str()
        .ok_or_else(|| ServerFnError::new("Archive path contains invalid UTF-8"))?;
    let extract_dir_str = extract_dir
        .to_str()
        .ok_or_else(|| ServerFnError::new("Extract directory path contains invalid UTF-8"))?;
    let tar_out = run_command_output_with_timeout(
        "tar",
        &[
            "-xzf",
            archive_path_str,
            "-C",
            extract_dir_str,
            "--no-absolute-filenames", // block absolute-path entries (tar slip defence)
            "--no-overwrite-dir",      // prevent replacing existing directories
        ],
        120,
    )
    .await?;

    if !tar_out.status.success() {
        return Err(ServerFnError::new(
            "tar extraction failed — archive may be corrupt.".to_string(),
        ));
    }

    let new_binary = extract_dir.join("panel");
    if !new_binary.exists() {
        return Err(ServerFnError::new(
            "panel binary not found inside archive.".to_string(),
        ));
    }

    // ── Step 6: atomically replace the installed binary ───────────────────
    const INSTALL_PATH: &str = "/opt/panel/panel";

    // Atomic swap: write to a sibling temp file, then rename
    let tmp_binary = "/opt/panel/panel.new";
    std::fs::copy(&new_binary, tmp_binary)
        .map_err(|e| ServerFnError::new(format!("Failed to copy binary to {tmp_binary}: {e}")))?;

    // Set permissions before moving into place
    let chmod_out = run_command_output_with_timeout("chmod", &["755", tmp_binary], 30).await?;
    if !chmod_out.status.success() {
        return Err(ServerFnError::new(
            "chmod 755 failed on the new binary — update aborted.".to_string(),
        ));
    }

    let chown_out =
        run_command_output_with_timeout("chown", &["panel:panel", tmp_binary], 30).await?;
    if !chown_out.status.success() {
        return Err(ServerFnError::new(
            "chown panel:panel failed on the new binary — update aborted.".to_string(),
        ));
    }

    std::fs::rename(tmp_binary, INSTALL_PATH)
        .map_err(|e| ServerFnError::new(format!("Failed to install new binary: {e}")))?;

    let _ = audit_log(
        claims.sub,
        "panel_update",
        Some("system"),
        None,
        Some(&release.html_url),
        "success",
        None,
    )
    .await;

    // ── Step 7: restart the panel service after returning the response ────
    tokio::spawn(async {
        use tokio::time::{timeout, Duration};

        tokio::time::sleep(Duration::from_secs(2)).await;
        if !crate::services::shell::is_allowed("systemctl") {
            tracing::error!("systemctl is not in the command allowlist; skipping panel restart");
            return;
        }
        if let Err(e) = timeout(
            Duration::from_secs(30),
            Command::new("systemctl")
                .args(["restart", "panel"])
                .status(),
        )
        .await
        {
            tracing::error!("Failed to restart panel service after update: {e:?}");
        }
    });

    Ok(PanelUpdateResult {
        success: true,
        message: format!("Panel updated to {tag}. Restarting…"),
    })
}

/// Get the most recent outcome of each heartbeat beat (admin only).
#[server]
pub async fn server_get_heartbeat_status() -> Result<HeartbeatStatus, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    async fn latest_beat(pool: &sqlx::SqlitePool, name: &str) -> Option<BeatInfo> {
        sqlx::query_as::<_, crate::models::task::BackgroundTask>(
            "SELECT * FROM background_tasks WHERE name = ? ORDER BY created_at DESC LIMIT 1",
        )
        .bind(name)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .map(|t| BeatInfo {
            last_ran_at: t.created_at,
            status: t.status,
            log_output: t.log_output,
        })
    }

    let (pulse, maintenance, quotas) = tokio::join!(
        latest_beat(pool, "heartbeat:pulse"),
        latest_beat(pool, "heartbeat:maintenance"),
        latest_beat(pool, "heartbeat:quotas"),
    );

    Ok(HeartbeatStatus {
        pulse,
        maintenance,
        quotas,
    })
}
