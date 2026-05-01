/// cgroups v2 resource limits via systemd user slices.
use crate::services::shell;
use tracing::warn;

const CGROUP_CONTROLLERS: &str = "/sys/fs/cgroup/cgroup.controllers";

/// Returns true if cgroups v2 is available.
pub fn is_cgroup_v2_available() -> bool {
    std::path::Path::new(CGROUP_CONTROLLERS).exists()
}

/// Apply resource limits for the given UID.
pub async fn apply_limits(uid: u32, cpu_percent: u32, memory_mb: u64, tasks_max: u32, io_weight: u32) -> Result<(), crate::services::ServiceError> {
    validate_uid(uid)?;
    if !is_cgroup_v2_available() {
        warn!(uid, "cgroups v2 not available; skipping limits");
        return Ok(());
    }
    let slice      = format!("user-{}.slice", uid);
    let cpu_quota  = format!("CPUQuota={}%", cpu_percent);
    let memory_max = format!("MemoryMax={}M", memory_mb);
    let tasks      = format!("TasksMax={}", tasks_max);
    let io         = format!("IOWeight={}", io_weight);
    shell::exec("systemctl", &["set-property", &slice, &cpu_quota, &memory_max, "MemorySwapMax=0", &tasks, &io]).await?;
    Ok(())
}

/// Suspend: throttle to minimal limits.
pub async fn suspend_limits(uid: u32) -> Result<(), crate::services::ServiceError> {
    validate_uid(uid)?;
    if !is_cgroup_v2_available() {
        warn!(uid, "cgroups v2 not available; skipping suspension");
        return Ok(());
    }
    let slice = format!("user-{}.slice", uid);
    shell::exec("systemctl", &["set-property", &slice, "CPUQuota=1%", "MemoryMax=64M", "MemorySwapMax=0", "TasksMax=5", "IOWeight=10"]).await?;
    Ok(())
}

/// Revert all runtime properties for the slice.
pub async fn reset_limits(uid: u32) -> Result<(), crate::services::ServiceError> {
    validate_uid(uid)?;
    if !is_cgroup_v2_available() {
        warn!(uid, "cgroups v2 not available; skipping revert");
        return Ok(());
    }
    let slice = format!("user-{}.slice", uid);
    shell::exec("systemctl", &["revert", &slice]).await?;
    Ok(())
}

fn validate_uid(uid: u32) -> Result<(), crate::services::ServiceError> {
    if uid < crate::services::osuser::UID_MIN || uid > crate::services::osuser::UID_MAX {
        return Err(crate::services::ServiceError::CommandFailed(format!(
            "UID {uid} outside allowed hosting range"
        )));
    }
    Ok(())
}
