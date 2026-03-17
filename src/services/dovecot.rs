/// Dovecot IMAP/POP3 server management.
/// Handles installation, virtual mailbox authentication, and lifecycle.
use super::{shell, ManagedService, ServiceError};
use crate::models::service::{ServiceStatus, ServiceType};
use async_trait::async_trait;
use std::path::Path;
use tokio::fs;
use tracing::info;

const DOVECOT_SERVICE: &str = "dovecot";
const DOVECOT_CONF_DIR: &str = "/etc/dovecot/conf.d";
const DOVECOT_USERS_FILE: &str = "/etc/dovecot/users";
const VIRTUAL_MAILBOX_BASE: &str = "/var/mail/vhosts";
const VMAIL_UID: &str = "5000";
const VMAIL_GID: &str = "5000";

/// Dovecot IMAP service manager.
pub struct DovecotService;

#[async_trait]
impl ManagedService for DovecotService {
    fn service_type(&self) -> ServiceType {
        ServiceType::Dovecot
    }

    async fn install(&self) -> Result<(), ServiceError> {
        info!("Installing Dovecot...");

        shell::exec(
            "apt-get",
            &[
                "install",
                "-y",
                "dovecot-core",
                "dovecot-imapd",
                "dovecot-pop3d",
                "dovecot-lmtpd",
                "dovecot-sieve",
            ],
        )
        .await?;

        shell::exec("systemctl", &["enable", DOVECOT_SERVICE]).await?;

        info!("Dovecot installed successfully");
        Ok(())
    }

    async fn start(&self) -> Result<(), ServiceError> {
        info!("Starting Dovecot...");
        shell::exec("systemctl", &["start", DOVECOT_SERVICE]).await?;
        Ok(())
    }

    async fn stop(&self) -> Result<(), ServiceError> {
        info!("Stopping Dovecot...");
        shell::exec("systemctl", &["stop", DOVECOT_SERVICE]).await?;
        Ok(())
    }

    async fn restart(&self) -> Result<(), ServiceError> {
        info!("Restarting Dovecot...");
        shell::exec("systemctl", &["restart", DOVECOT_SERVICE]).await?;
        Ok(())
    }

    async fn status(&self) -> Result<ServiceStatus, ServiceError> {
        match shell::exec("systemctl", &["is-active", DOVECOT_SERVICE]).await {
            Ok(output) => {
                let status_str = String::from_utf8_lossy(&output.stdout);
                if status_str.trim() == "active" {
                    Ok(ServiceStatus::Running)
                } else {
                    Ok(ServiceStatus::Stopped)
                }
            }
            Err(_) => Ok(ServiceStatus::Unknown),
        }
    }

    async fn is_installed(&self) -> Result<bool, ServiceError> {
        Ok(Path::new("/usr/sbin/dovecot").exists())
    }

    async fn version(&self) -> Result<String, ServiceError> {
        let output = shell::exec("dovecot", &["--version"]).await?;
        let version = String::from_utf8_lossy(&output.stdout);
        Ok(version.trim().to_string())
    }
}

impl DovecotService {
    /// Configure Dovecot for virtual mailbox hosting with passwd-file auth.
    pub async fn configure_virtual_hosting(&self) -> Result<(), ServiceError> {
        info!("Configuring Dovecot for virtual hosting...");

        // Create users file if it doesn't exist
        if !Path::new(DOVECOT_USERS_FILE).exists() {
            fs::write(DOVECOT_USERS_FILE, "")
                .await
                .map_err(|e| ServiceError::IoError(e.to_string()))?;
        }

        // Write auth configuration
        let auth_conf = generate_auth_conf();
        fs::write(format!("{}/10-auth.conf", DOVECOT_CONF_DIR), auth_conf)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        // Write mail location configuration
        let mail_conf = generate_mail_conf();
        fs::write(format!("{}/10-mail.conf", DOVECOT_CONF_DIR), mail_conf)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        // Write SSL configuration
        let ssl_conf = generate_ssl_conf();
        fs::write(format!("{}/10-ssl.conf", DOVECOT_CONF_DIR), ssl_conf)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        // Write master configuration (LMTP + auth socket for Postfix)
        let master_conf = generate_master_conf();
        fs::write(format!("{}/10-master.conf", DOVECOT_CONF_DIR), master_conf)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        // Write passwd-file auth backend
        let passwd_conf = generate_passwd_file_conf();
        fs::write(
            format!("{}/auth-passwdfile.conf.ext", DOVECOT_CONF_DIR),
            passwd_conf,
        )
        .await
        .map_err(|e| ServiceError::IoError(e.to_string()))?;

        self.restart().await?;
        info!("Dovecot virtual hosting configured");
        Ok(())
    }

    /// Add a virtual user to the Dovecot passwd-file.
    /// Password should already be hashed (e.g., with Argon2 or SHA512-CRYPT).
    pub async fn add_user(
        &self,
        email: &str,
        password_hash: &str,
        domain: &str,
        quota_mb: Option<i64>,
    ) -> Result<(), ServiceError> {
        // Defense-in-depth: validate inputs at service layer
        crate::utils::validators::validate_email(email)
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;
        crate::utils::validators::validate_domain(domain)
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;
        // Verify password_hash is actually a SHA512-CRYPT hash (starts with $6$)
        if !password_hash.starts_with("$6$") {
            return Err(ServiceError::CommandFailed(
                "Password hash must be SHA512-CRYPT format (starting with $6$)".to_string(),
            ));
        }
        crate::utils::validators::validate_passwd_field(password_hash, "password_hash")
            .map_err(ServiceError::CommandFailed)?;
        // Validate quota: must be a positive value within a sane ceiling (10 TiB).
        if let Some(mb) = quota_mb {
            if mb <= 0 || mb > 10_485_760 {
                return Err(ServiceError::CommandFailed(
                    "Quota must be between 1 MB and 10,485,760 MB (10 TiB)".to_string(),
                ));
            }
        };

        info!("Adding Dovecot user: {}", email);

        let _lock = super::filelock::FileLock::exclusive(DOVECOT_USERS_FILE)?;

        let mut content = fs::read_to_string(DOVECOT_USERS_FILE)
            .await
            .unwrap_or_default();

        let quota_rule = quota_mb
            .map(|mb| format!("userdb_quota_rule=*:storage={}M", mb))
            .unwrap_or_default();

        // Format: user:{scheme}password:uid:gid:gecos:home:extra_fields
        let home = format!("{}/{}/{}", VIRTUAL_MAILBOX_BASE, domain, email);
        // Defense-in-depth: ensure the computed home path cannot corrupt the
        // colon-delimited passwd file format (validate_domain/validate_email
        // already reject colons, but we check here as an extra layer).
        if home.contains(':') || home.contains('\n') || home.contains('\r') {
            return Err(ServiceError::CommandFailed(
                "Computed home path contains characters that would corrupt the passwd file format"
                    .to_string(),
            ));
        }
        let entry = format!(
            "{}:{{SHA512-CRYPT}}{}:{}:{}::{}:{}\n",
            email, password_hash, VMAIL_UID, VMAIL_GID, home, quota_rule
        );

        // Remove existing entry for this user if present
        content = content
            .lines()
            .filter(|line| !line.starts_with(&format!("{}:", email)))
            .map(|line| format!("{}\n", line))
            .collect();

        content.push_str(&entry);

        let users_tmp = format!("{}.tmp", DOVECOT_USERS_FILE);
        fs::write(&users_tmp, &content)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;
        fs::rename(&users_tmp, DOVECOT_USERS_FILE)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        // Create home directory
        shell::exec("mkdir", &["-p", &home]).await?;
        shell::exec(
            "chown",
            &["-R", &format!("{}:{}", VMAIL_UID, VMAIL_GID), &home],
        )
        .await?;

        Ok(())
    }

    /// Remove a virtual user from the Dovecot passwd-file.
    pub async fn remove_user(&self, email: &str) -> Result<(), ServiceError> {
        crate::utils::validators::validate_email(email)
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;

        info!("Removing Dovecot user: {}", email);

        let _lock = super::filelock::FileLock::exclusive(DOVECOT_USERS_FILE)?;

        let content = fs::read_to_string(DOVECOT_USERS_FILE)
            .await
            .unwrap_or_default();

        let new_content: String = content
            .lines()
            .filter(|line| !line.starts_with(&format!("{}:", email)))
            .map(|line| format!("{}\n", line))
            .collect();

        let users_tmp = format!("{}.tmp", DOVECOT_USERS_FILE);
        fs::write(&users_tmp, &new_content)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;
        fs::rename(&users_tmp, DOVECOT_USERS_FILE)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        Ok(())
    }

    /// Update a user's password in the passwd-file.
    pub async fn update_password(
        &self,
        email: &str,
        password_hash: &str,
    ) -> Result<(), ServiceError> {
        crate::utils::validators::validate_email(email)
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;
        // Verify password_hash is actually a SHA512-CRYPT hash
        if !password_hash.starts_with("$6$") {
            return Err(ServiceError::CommandFailed(
                "Password hash must be SHA512-CRYPT format (starting with $6$)".to_string(),
            ));
        }
        // Defense-in-depth: ensure hash contains no injection characters
        crate::utils::validators::validate_passwd_field(password_hash, "password_hash")
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;

        let _lock = super::filelock::FileLock::exclusive(DOVECOT_USERS_FILE)?;

        let content = fs::read_to_string(DOVECOT_USERS_FILE)
            .await
            .unwrap_or_default();

        let new_content: String = content
            .lines()
            .map(|line| {
                if line.starts_with(&format!("{}:", email)) {
                    // Replace the password field (second field)
                    let parts: Vec<&str> = line.splitn(3, ':').collect();
                    if parts.len() >= 3 {
                        format!(
                            "{}:{{SHA512-CRYPT}}{}:{}",
                            parts[0], password_hash, parts[2]
                        )
                    } else {
                        line.to_string()
                    }
                } else {
                    line.to_string()
                }
            })
            .map(|line| format!("{}\n", line))
            .collect();

        let users_tmp = format!("{}.tmp", DOVECOT_USERS_FILE);
        fs::write(&users_tmp, &new_content)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;
        fs::rename(&users_tmp, DOVECOT_USERS_FILE)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        Ok(())
    }
}

/// Generate Dovecot 10-auth.conf for virtual user authentication.
fn generate_auth_conf() -> String {
    r#"# Dovecot 10-auth.conf - Managed by Hosting Control Panel
# Do not edit manually.

disable_plaintext_auth = yes
auth_mechanisms = plain login

# Use passwd-file for virtual users
!include auth-passwdfile.conf.ext
"#
    .to_string()
}

/// Generate Dovecot 10-mail.conf for virtual mailbox storage.
fn generate_mail_conf() -> String {
    format!(
        r#"# Dovecot 10-mail.conf - Managed by Hosting Control Panel
# Do not edit manually.

mail_location = maildir:{vmailbase}/%d/%n
mail_home = {vmailbase}/%d/%n

namespace inbox {{
  inbox = yes
  separator = /

  mailbox Drafts {{
    auto = subscribe
    special_use = \Drafts
  }}
  mailbox Junk {{
    auto = subscribe
    special_use = \Junk
  }}
  mailbox Sent {{
    auto = subscribe
    special_use = \Sent
  }}
  mailbox Trash {{
    auto = subscribe
    special_use = \Trash
  }}
  mailbox Archive {{
    auto = no
    special_use = \Archive
  }}
}}

mail_uid = {uid}
mail_gid = {gid}
mail_privileged_group = {gid}
first_valid_uid = {uid}
last_valid_uid = {uid}

# Quota support
mail_plugins = $mail_plugins quota
"#,
        vmailbase = VIRTUAL_MAILBOX_BASE,
        uid = VMAIL_UID,
        gid = VMAIL_GID,
    )
}

/// Generate Dovecot 10-ssl.conf.
fn generate_ssl_conf() -> String {
    r#"# Dovecot 10-ssl.conf - Managed by Hosting Control Panel
# Do not edit manually.

ssl = required
ssl_cert = </etc/ssl/certs/ssl-cert-snakeoil.pem
ssl_key = </etc/ssl/private/ssl-cert-snakeoil.key

ssl_min_protocol = TLSv1.2
ssl_prefer_server_ciphers = yes
"#
    .to_string()
}

/// Generate Dovecot 10-master.conf with LMTP and Postfix auth integration.
fn generate_master_conf() -> String {
    r#"# Dovecot 10-master.conf - Managed by Hosting Control Panel
# Do not edit manually.

service imap-login {
  inet_listener imap {
    port = 143
  }
  inet_listener imaps {
    port = 993
    ssl = yes
  }
}

service pop3-login {
  inet_listener pop3 {
    port = 110
  }
  inet_listener pop3s {
    port = 995
    ssl = yes
  }
}

service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0600
    user = postfix
    group = postfix
  }
}

service auth {
  # Postfix SASL authentication
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }

  unix_listener auth-userdb {
    mode = 0660
  }
}

service auth-worker {
}
"#
    .to_string()
}

/// Generate Dovecot passwd-file authentication backend config.
fn generate_passwd_file_conf() -> String {
    format!(
        r#"# Dovecot passwd-file auth - Managed by Hosting Control Panel
# Do not edit manually.

passdb {{
  driver = passwd-file
  args = scheme=SHA512-CRYPT username_format=%u {users_file}
}}

userdb {{
  driver = passwd-file
  args = username_format=%u {users_file}
  default_fields = uid={uid} gid={gid} home={vmailbase}/%d/%n
}}
"#,
        users_file = DOVECOT_USERS_FILE,
        uid = VMAIL_UID,
        gid = VMAIL_GID,
        vmailbase = VIRTUAL_MAILBOX_BASE,
    )
}

impl DovecotService {
    /// Update the Dovecot 10-ssl.conf to use the provided TLS certificate and key.
    pub async fn update_ssl_cert(
        &self,
        cert_path: &str,
        key_path: &str,
    ) -> Result<(), super::ServiceError> {
        // Reject paths that could inject Dovecot config directives or escape
        // the permitted certificate directories.
        for (label, path) in &[("cert_path", cert_path), ("key_path", key_path)] {
            if path.contains('\n')
                || path.contains('\r')
                || path.contains('\0')
                || path.contains("..")
            {
                return Err(super::ServiceError::CommandFailed(format!(
                    "SSL {label} contains invalid characters"
                )));
            }
            let allowed = path.starts_with("/etc/letsencrypt/")
                || path.starts_with("/etc/ssl/panel/")
                || path.starts_with("/etc/ssl/");
            if !allowed {
                return Err(super::ServiceError::CommandFailed(format!(
                    "SSL {label} is outside permitted certificate directories"
                )));
            }
        }
        let ssl_conf_path = format!("{}/10-ssl.conf", DOVECOT_CONF_DIR);
        let ssl_conf_tmp = format!("{}.tmp", ssl_conf_path);
        let content = format!(
            "ssl = required\nssl_cert = <{cert_path}\nssl_key = <{key_path}\n",
            cert_path = cert_path,
            key_path = key_path,
        );
        // Write atomically: tmp file + rename so that a crash can never produce
        // a partially-written ssl config that would break Dovecot.
        tokio::fs::write(&ssl_conf_tmp, &content)
            .await
            .map_err(|e| super::ServiceError::IoError(e.to_string()))?;
        tokio::fs::rename(&ssl_conf_tmp, &ssl_conf_path)
            .await
            .map_err(|e| super::ServiceError::IoError(e.to_string()))?;
        // Reload Dovecot to pick up the new cert.
        super::shell::exec("systemctl", &["reload", DOVECOT_SERVICE])
            .await
            .map_err(|e| super::ServiceError::CommandFailed(e.to_string()))?;
        Ok(())
    }
}
