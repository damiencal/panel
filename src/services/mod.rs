/// System service management module.
/// Each managed service (OpenLiteSpeed, MariaDB, etc.) implements
/// the ManagedService trait for consistent lifecycle management.
pub mod awstats;
pub mod basic_auth;
pub mod certbot;
pub mod clamav_stub;
#[cfg(feature = "server")]
pub mod cloudflare;
pub mod dkim;
pub mod dovecot;
pub mod git;
pub mod goaccess;
pub mod janitor;
pub mod mail_queue;
pub mod mailscanner;
pub mod mariadb;
pub mod modsecurity;
pub mod openlitespeed;
pub mod phpmyadmin;
pub mod postfix;
pub mod postfix_policy;
pub mod pureftpd;
pub mod rspamd;
pub mod spamassassin;
pub mod ssh_hardening;
pub mod system;
pub mod ufw;
pub mod webalizer;

use crate::models::service::{ServiceStatus, ServiceType};
use async_trait::async_trait;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("Service command failed: {0}")]
    CommandFailed(String),
    #[error("Service not installed")]
    NotInstalled,
    #[error("Permission denied")]
    PermissionDenied,
    #[error("IO error: {0}")]
    IoError(String),
}

/// Core trait that all managed services must implement.
#[async_trait]
pub trait ManagedService {
    fn service_type(&self) -> ServiceType;

    async fn install(&self) -> Result<(), ServiceError>;
    async fn start(&self) -> Result<(), ServiceError>;
    async fn stop(&self) -> Result<(), ServiceError>;
    async fn restart(&self) -> Result<(), ServiceError>;
    async fn status(&self) -> Result<ServiceStatus, ServiceError>;
    async fn is_installed(&self) -> Result<bool, ServiceError>;
    async fn version(&self) -> Result<String, ServiceError>;
}

/// Safe command execution helper.
pub mod shell {
    use super::ServiceError;
    use std::process::Output;
    use tokio::process::Command;

    const ALLOWED_BINARIES: &[&str] = &[
        "systemctl",
        "lswsctrl",
        "certbot",
        "mysql",
        "psql",
        "useradd",
        "userdel",
        "groupadd",
        "chown",
        "chmod",
        "ufw",
        "iptables",
        "postfix",
        "postmap",
        "dovecot",
        "doveadm",
        "pure-ftpd",
        "pure-pw",
        "lsphp",
        "php",
        "openssl",
        "mkdir",
        "rm",
        "cp",
        "mv",
        "chown",
        "chmod",
        "tar",
        "zip",
        "unzip",
        "curl",
        "wget",
        "which",
        "mariadb",
        "apt-get",
        "opendkim-genkey",
        "opendkim",
        "spamassassin",
        "spamc",
        "rspamd",
        "rspamc",
        "clamscan",
        "freshclam",
        "clamdscan",
        "MailScanner",
        "postqueue",
        "postsuper",
        "postconf",
        "webalizer",
        "goaccess",
        "perl",
        "awstats",
        "mysqldump",
        "kill",
        "dpkg",
        // Used by git.rs for site-user-scoped operations — git.rs validates args
        // at each call site before invoking these binaries.
        "sudo",
        "ssh-keygen",
        "ssh-keyscan",
        "ln",
        "bash",
        "timeout",
        "git",
        // Used by system.rs for read-only diagnostics (version checks, service status)
        "pgrep",
        "sshd",
        "service",
        "dpkg-query",
        "df",
        "docker",
        "find",
        "lshttpd",
        "pgrep",
    ];

    /// Validate that shell arguments don't contain injection characters.
    /// Note: since we use Command::new (not a shell), only characters that are
    /// dangerous when passed directly to programs need to be blocked. Parentheses
    /// are safe since they have no special meaning outside of a shell context.
    fn validate_args(args: &[&str]) -> Result<(), ServiceError> {
        for arg in args {
            if arg.contains([';', '|', '&', '$', '`', '\n', '\r']) {
                return Err(ServiceError::CommandFailed(format!(
                    "Invalid characters in argument: {}",
                    arg
                )));
            }
        }
        Ok(())
    }

    /// Execute a shell command safely (allowlisted binaries only + argument validation).
    pub async fn exec(cmd: &str, args: &[&str]) -> Result<Output, ServiceError> {
        let binary = cmd.split('/').next_back().unwrap_or(cmd);

        if !ALLOWED_BINARIES.contains(&binary) {
            return Err(ServiceError::PermissionDenied);
        }

        validate_args(args)?;

        let output = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            Command::new(cmd).args(args).output(),
        )
        .await
        .map_err(|_| ServiceError::CommandFailed("command timed out after 30s".to_string()))?
        .map_err(|e| ServiceError::IoError(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ServiceError::CommandFailed(stderr.to_string()));
        }

        Ok(output)
    }

    /// Execute a shell command with data piped to its stdin.
    /// Use this for MySQL/MariaDB commands that contain credentials in the SQL statement
    /// so the password is never visible in the process argument list (`ps aux`).
    pub async fn exec_stdin(
        cmd: &str,
        args: &[&str],
        stdin_data: &[u8],
    ) -> Result<Output, ServiceError> {
        use tokio::io::AsyncWriteExt;

        let binary = cmd.split('/').next_back().unwrap_or(cmd);
        if !ALLOWED_BINARIES.contains(&binary) {
            return Err(ServiceError::PermissionDenied);
        }
        validate_args(args)?;

        let mut child = Command::new(cmd)
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(stdin_data)
                .await
                .map_err(|e| ServiceError::IoError(e.to_string()))?;
        }

        let output =
            tokio::time::timeout(std::time::Duration::from_secs(30), child.wait_with_output())
                .await
                .map_err(|_| {
                    ServiceError::CommandFailed("command timed out after 30s".to_string())
                })?
                .map_err(|e| ServiceError::IoError(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ServiceError::CommandFailed(stderr.to_string()));
        }

        Ok(output)
    }

    /// Check if a binary exists in PATH.
    pub async fn command_exists(cmd: &str) -> bool {
        Command::new("which")
            .arg(cmd)
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

/// File locking utility for safe read-modify-write operations.
/// Prevents TOCTOU race conditions when concurrent operations modify the same file.
pub mod filelock {
    use std::os::unix::io::AsRawFd;
    use std::path::Path;

    pub struct FileLock {
        _file: std::fs::File,
    }

    impl FileLock {
        /// Acquire an exclusive lock on the given path (blocking).
        /// The lock is held until the returned `FileLock` is dropped.
        pub fn exclusive(path: impl AsRef<Path>) -> Result<Self, super::ServiceError> {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(path.as_ref().with_extension("lock"))
                .map_err(|e| super::ServiceError::IoError(e.to_string()))?;

            // LOCK_EX = exclusive, blocking
            let rc = unsafe { nix::libc::flock(file.as_raw_fd(), nix::libc::LOCK_EX) };
            if rc != 0 {
                return Err(super::ServiceError::IoError(
                    "Failed to acquire file lock".to_string(),
                ));
            }

            Ok(FileLock { _file: file })
        }
    }

    impl Drop for FileLock {
        fn drop(&mut self) {
            // Lock is automatically released when the file descriptor is closed
        }
    }
}
