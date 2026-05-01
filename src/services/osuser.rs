/// OS user management for hosting accounts.
use crate::services::shell;
use crate::utils::validators::validate_username;
use std::collections::HashSet;
use tracing::{info, warn};

pub const HOME_BASE: &str = "/home";
pub const UID_MIN: u32 = 10_000;
pub const UID_MAX: u32 = 59_999;
pub const ARCHIVE_DIR: &str = "/var/panel/archives";

/// Create an OS user with the given username and UID.
pub async fn create_user(username: &str, uid: u32) -> Result<(), crate::services::ServiceError> {
    validate_username(username)
        .map_err(|e| crate::services::ServiceError::CommandFailed(e.to_string()))?;
    validate_uid(uid)?;

    let home = format!("{}/{}", HOME_BASE, username);
    let uid_str = uid.to_string();

    shell::exec("useradd", &["-m", "-s", "/bin/bash", "-u", &uid_str, "-U", username]).await?;
    shell::exec("chmod", &["750", &home]).await?;

    let public_html = format!("{}/public_html", home);
    let logs        = format!("{}/logs", home);
    let tmp         = format!("{}/tmp", home);
    shell::exec("mkdir", &["-p", &public_html, &logs, &tmp]).await?;
    shell::exec("chmod", &["700", &tmp]).await?;

    let owner = format!("{}:{}", username, username);
    shell::exec("chown", &["-R", &owner, &home]).await?;

    info!("Created OS user '{}' (uid={})", username, uid);
    Ok(())
}

/// Delete an OS user (idempotent).
pub async fn delete_user(username: &str) -> Result<(), crate::services::ServiceError> {
    validate_username(username)
        .map_err(|e| crate::services::ServiceError::CommandFailed(e.to_string()))?;
    match shell::exec("userdel", &["-r", username]).await {
        Ok(_) => { info!("Deleted OS user '{}'", username); Ok(()) }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("does not exist") || msg.contains("exit code: 6") {
                warn!("OS user '{}' did not exist; ignoring", username);
                Ok(())
            } else {
                Err(e)
            }
        }
    }
}

/// Archive the home directory before account deletion.
pub async fn archive_home(username: &str) -> Result<(), crate::services::ServiceError> {
    validate_username(username)
        .map_err(|e| crate::services::ServiceError::CommandFailed(e.to_string()))?;
    shell::exec("mkdir", &["-p", ARCHIVE_DIR]).await?;
    let archive = format!("{}/{}.tar.gz", ARCHIVE_DIR, username);
    shell::exec("tar", &["-czf", &archive, "-C", HOME_BASE, username]).await?;
    info!("Archived home for '{}' to '{}'", username, archive);
    Ok(())
}

/// Return the next available UID in the hosting range [UID_MIN, UID_MAX].
pub async fn get_next_uid() -> Result<u32, crate::services::ServiceError> {
    let output = shell::exec_output("getent", &["passwd"]).await?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    let used: HashSet<u32> = stdout.lines()
        .filter_map(|line| {
            let mut parts = line.splitn(4, ':');
            parts.next();
            parts.next();
            parts.next().and_then(|s| s.parse::<u32>().ok())
        })
        .collect();

    for uid in UID_MIN..=UID_MAX {
        if !used.contains(&uid) {
            return Ok(uid);
        }
    }
    Err(crate::services::ServiceError::CommandFailed("UID range exhausted".to_string()))
}

/// Prune archives older than max_days days (best-effort).
pub async fn prune_old_archives(max_days: u32) -> usize {
    let days = format!("+{}", max_days);
    if let Err(e) = shell::exec("find", &[ARCHIVE_DIR, "-name", "*.tar.gz", "-mtime", &days, "-delete"]).await {
        warn!("Archive pruning failed: {e}");
    }
    0
}

fn validate_uid(uid: u32) -> Result<(), crate::services::ServiceError> {
    if uid < UID_MIN || uid > UID_MAX {
        return Err(crate::services::ServiceError::CommandFailed(format!(
            "UID {uid} outside allowed range {UID_MIN}-{UID_MAX}"
        )));
    }
    Ok(())
}
