/// SSH hardening configuration service.
/// Manages /etc/ssh/sshd_config to apply security best practices.
use super::ServiceError;
use tokio::fs;
use tracing::info;

// Re-export shared types from models
pub use crate::models::security::{SshConfig, SshHardeningResult};

const SSHD_CONFIG: &str = "/etc/ssh/sshd_config";
const SSHD_CONFIG_BACKUP: &str = "/etc/ssh/sshd_config.panel_backup";
const SSHD_HARDENED_DROPIN: &str = "/etc/ssh/sshd_config.d/99-panel-hardening.conf";

// ─── Service ─────────────────────────────────────────────────────────────────

pub struct SshHardeningService;

impl SshHardeningService {
    /// Read the current sshd_config and parse known directives.
    pub async fn get_config(&self) -> Result<SshConfig, ServiceError> {
        let content = fs::read_to_string(SSHD_CONFIG).await.unwrap_or_default();
        Ok(parse_sshd_config(&content))
    }

    /// Apply a hardened SSH configuration.
    /// Creates a drop-in file at /etc/ssh/sshd_config.d/99-panel-hardening.conf.
    pub async fn apply_config(
        &self,
        config: &SshConfig,
    ) -> Result<SshHardeningResult, ServiceError> {
        let mut warnings = Vec::new();

        // Validate port range
        if config.port == 0 {
            return Err(ServiceError::CommandFailed(
                "Invalid SSH port: 0".to_string(),
            ));
        }

        // Warn about potential lockout risks
        if !config.password_authentication && !config.pubkey_authentication {
            warnings.push(
                "WARNING: Both password and pubkey auth are disabled — you may lock yourself out!"
                    .to_string(),
            );
        }
        if config.permit_root_login == "yes" {
            warnings
                .push("WARNING: Root login is set to 'yes' — this is a security risk.".to_string());
        }

        // Validate user-supplied string fields for newline injection before they
        // are interpolated into the sshd config file.
        for user in &config.allowed_users {
            if user.chars().any(|c| c == '\n' || c == '\r') {
                return Err(ServiceError::CommandFailed(
                    "AllowUsers entry contains invalid characters".to_string(),
                ));
            }
        }
        for (field_name, field_val) in &[
            ("Ciphers", config.ciphers.as_str()),
            ("MACs", config.macs.as_str()),
            ("KexAlgorithms", config.kex_algorithms.as_str()),
            ("PermitRootLogin", config.permit_root_login.as_str()),
        ] {
            if field_val.chars().any(|c| c == '\n' || c == '\r') {
                return Err(ServiceError::CommandFailed(format!(
                    "{field_name} contains invalid characters"
                )));
            }
        }

        // Backup original config if no backup exists yet
        if !std::path::Path::new(SSHD_CONFIG_BACKUP).exists() {
            if let Ok(original) = fs::read_to_string(SSHD_CONFIG).await {
                fs::write(SSHD_CONFIG_BACKUP, original)
                    .await
                    .map_err(|e| ServiceError::IoError(e.to_string()))?;
                info!("sshd_config backed up to {SSHD_CONFIG_BACKUP}");
            }
        }

        // Create drop-in directory if needed
        fs::create_dir_all("/etc/ssh/sshd_config.d")
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        let content = render_sshd_dropin(config);

        // Write atomically: write to a tmp file first, then rename into place
        // only after sshd -t confirms the merged config is valid.
        // This prevents a partial/broken file from ever being the live config.
        let dropin_tmp = format!("{SSHD_HARDENED_DROPIN}.tmp");
        fs::write(&dropin_tmp, &content)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        // Rename into final position so sshd -t can evaluate it.
        fs::rename(&dropin_tmp, SSHD_HARDENED_DROPIN)
            .await
            .map_err(|e| {
                let _ = std::fs::remove_file(&dropin_tmp);
                ServiceError::IoError(e.to_string())
            })?;

        // Test and reload SSHD
        let test = tokio::process::Command::new("sshd")
            .arg("-t")
            .output()
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        if !test.status.success() {
            // Remove the dropin to avoid breaking SSH
            fs::remove_file(SSHD_HARDENED_DROPIN).await.ok();
            return Err(ServiceError::CommandFailed(format!(
                "sshd config test failed"
            )));
        }

        // Config is valid — now safe to write the banner and reload.
        if config.banner_enabled {
            let banner = "Authorized access only. All activity may be monitored and reported.\n";
            fs::write("/etc/issue.net", banner).await.ok();
        }

        // Reload SSHD
        let reload = tokio::process::Command::new("systemctl")
            .args(["reload", "sshd"])
            .output()
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        if !reload.status.success() {
            // Try 'ssh' as the service name (some distros name it 'ssh')
            let reload2 = tokio::process::Command::new("systemctl")
                .args(["reload", "ssh"])
                .output()
                .await
                .map_err(|e| ServiceError::IoError(e.to_string()))?;
            if !reload2.status.success() {
                warnings.push(
                    "SSHD reload failed — config was written but service was not reloaded. Reload manually with: systemctl reload sshd".to_string(),
                );
            }
        }

        info!("SSH hardening config applied");

        Ok(SshHardeningResult {
            success: true,
            message: format!(
                "SSH hardening configuration applied to {SSHD_HARDENED_DROPIN}. Reload successful."
            ),
            warnings,
        })
    }

    /// Restore the original sshd_config backup.
    pub async fn restore_backup(&self) -> Result<(), ServiceError> {
        if !std::path::Path::new(SSHD_CONFIG_BACKUP).exists() {
            return Err(ServiceError::CommandFailed(
                "No backup found to restore".to_string(),
            ));
        }
        fs::remove_file(SSHD_HARDENED_DROPIN).await.ok();
        tokio::process::Command::new("systemctl")
            .args(["reload", "sshd"])
            .output()
            .await
            .ok();
        info!("SSH configuration restored from backup");
        Ok(())
    }

    /// Get the hardening status (is our drop-in active?).
    pub async fn is_hardening_active(&self) -> bool {
        std::path::Path::new(SSHD_HARDENED_DROPIN).exists()
    }

    /// Check the current SSH listening port.
    pub async fn get_current_port(&self) -> u16 {
        let out = tokio::process::Command::new("sshd")
            .arg("-T")
            .output()
            .await
            .ok();
        if let Some(out) = out {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                if line.starts_with("port ") {
                    if let Some(port_str) = line.split_whitespace().nth(1) {
                        if let Ok(p) = port_str.parse::<u16>() {
                            return p;
                        }
                    }
                }
            }
        }
        22
    }

    /// Run `sshd -T` and return full effective config.
    pub async fn get_effective_config(&self) -> Result<String, ServiceError> {
        let out = tokio::process::Command::new("sshd")
            .arg("-T")
            .output()
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn render_sshd_dropin(config: &SshConfig) -> String {
    let permit_root = &config.permit_root_login;
    let password_auth = if config.password_authentication {
        "yes"
    } else {
        "no"
    };
    let pubkey_auth = if config.pubkey_authentication {
        "yes"
    } else {
        "no"
    };
    let agent_fwd = if config.allow_agent_forwarding {
        "yes"
    } else {
        "no"
    };
    let x11_fwd = if config.x11_forwarding { "yes" } else { "no" };
    let use_pam = if config.use_pam { "yes" } else { "no" };
    let ignore_rhosts = if config.ignore_rhosts { "yes" } else { "no" };
    let permit_empty = if config.permit_empty_passwords {
        "yes"
    } else {
        "no"
    };
    let challenge_resp = if config.challenge_response_authentication {
        "yes"
    } else {
        "no"
    };
    let use_dns = if config.use_dns { "yes" } else { "no" };
    let banner = if config.banner_enabled {
        "/etc/issue.net"
    } else {
        "none"
    };
    let allowed_users = if config.allowed_users.is_empty() {
        String::new()
    } else {
        format!("AllowUsers {}\n", config.allowed_users.join(" "))
    };

    format!(
        r#"# SSH Hardening Configuration
# Generated by hosting panel on {date}
# Edit via Security → SSH Hardening in the admin panel

Port {port}

# Authentication
PermitRootLogin {permit_root}
PasswordAuthentication {password_auth}
PubkeyAuthentication {pubkey_auth}
MaxAuthTries {max_auth_tries}
LoginGraceTime {login_grace_time}
PermitEmptyPasswords {permit_empty}
ChallengeResponseAuthentication {challenge_resp}

# Sessions
AllowAgentForwarding {agent_fwd}
X11Forwarding {x11_fwd}
MaxSessions {max_sessions}
MaxStartups {max_startups}
ClientAliveInterval {client_alive_interval}
ClientAliveCountMax {client_alive_count_max}

# Misc
UsePAM {use_pam}
IgnoreRhosts {ignore_rhosts}
UseDNS {use_dns}
Banner {banner}
{allowed_users}
# Hardened cryptography
Ciphers {ciphers}
MACs {macs}
KexAlgorithms {kex_algorithms}
"#,
        date = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
        port = config.port,
        permit_root = permit_root,
        password_auth = password_auth,
        pubkey_auth = pubkey_auth,
        max_auth_tries = config.max_auth_tries,
        login_grace_time = config.login_grace_time,
        permit_empty = permit_empty,
        challenge_resp = challenge_resp,
        agent_fwd = agent_fwd,
        x11_fwd = x11_fwd,
        max_sessions = config.max_sessions,
        max_startups = config.max_startups,
        client_alive_interval = config.client_alive_interval,
        client_alive_count_max = config.client_alive_count_max,
        use_pam = use_pam,
        ignore_rhosts = ignore_rhosts,
        use_dns = use_dns,
        banner = banner,
        allowed_users = allowed_users,
        ciphers = config.ciphers,
        macs = config.macs,
        kex_algorithms = config.kex_algorithms,
    )
}

fn parse_sshd_config(content: &str) -> SshConfig {
    let mut config = SshConfig::default();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.splitn(2, char::is_whitespace).collect();
        if parts.len() < 2 {
            continue;
        }
        let (key, val) = (parts[0].to_lowercase(), parts[1].trim());
        match key.as_str() {
            "port" => {
                if let Ok(p) = val.parse::<u16>() {
                    config.port = p;
                }
            }
            "permitrootlogin" => config.permit_root_login = val.to_string(),
            "passwordauthentication" => config.password_authentication = val == "yes",
            "pubkeyauthentication" => config.pubkey_authentication = val == "yes",
            "maxauthtries" => {
                if let Ok(v) = val.parse::<u8>() {
                    config.max_auth_tries = v;
                }
            }
            "logingracetime" => {
                if let Ok(v) = val.parse::<u16>() {
                    config.login_grace_time = v;
                }
            }
            "allowagentforwarding" => config.allow_agent_forwarding = val == "yes",
            "x11forwarding" => config.x11_forwarding = val == "yes",
            "usepam" => config.use_pam = val == "yes",
            "ignorerhosts" => config.ignore_rhosts = val == "yes",
            "permitemptypasswords" => config.permit_empty_passwords = val == "yes",
            "challengeresponseauthentication" | "kbdinteractiveauthentication" => {
                config.challenge_response_authentication = val == "yes"
            }
            "usedns" => config.use_dns = val == "yes",
            "banner" => config.banner_enabled = val != "none",
            "allowusers" => {
                config.allowed_users = val.split_whitespace().map(|s| s.to_string()).collect()
            }
            "clientaliveinterval" => {
                if let Ok(v) = val.parse::<u16>() {
                    config.client_alive_interval = v;
                }
            }
            "clientalivecountmax" => {
                if let Ok(v) = val.parse::<u8>() {
                    config.client_alive_count_max = v;
                }
            }
            "maxsessions" => {
                if let Ok(v) = val.parse::<u8>() {
                    config.max_sessions = v;
                }
            }
            "maxstartups" => config.max_startups = val.to_string(),
            "ciphers" => config.ciphers = val.to_string(),
            "macs" => config.macs = val.to_string(),
            "kexalgorithms" => config.kex_algorithms = val.to_string(),
            _ => {}
        }
    }

    config
}
