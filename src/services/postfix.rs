/// Postfix mail transfer agent management.
/// Handles installation, virtual domain/mailbox configuration, and lifecycle.
use super::{shell, ManagedService, ServiceError};
use crate::models::service::{ServiceStatus, ServiceType};
use async_trait::async_trait;
use std::path::Path;
use tokio::fs;
use tracing::info;

const POSTFIX_SERVICE: &str = "postfix";
const POSTFIX_MAIN_CF: &str = "/etc/postfix/main.cf";
const VIRTUAL_MAILBOX_BASE: &str = "/var/mail/vhosts";
const VIRTUAL_DOMAINS_FILE: &str = "/etc/postfix/virtual_domains";
const VIRTUAL_MAILBOX_FILE: &str = "/etc/postfix/virtual_mailboxes";
const VIRTUAL_ALIAS_FILE: &str = "/etc/postfix/virtual_aliases";
const VMAIL_USER: &str = "vmail";
const VMAIL_UID: &str = "5000";
const VMAIL_GID: &str = "5000";

/// Postfix MTA service manager.
pub struct PostfixService;

#[async_trait]
impl ManagedService for PostfixService {
    fn service_type(&self) -> ServiceType {
        ServiceType::Postfix
    }

    async fn install(&self) -> Result<(), ServiceError> {
        info!("Installing Postfix...");

        shell::exec("apt-get", &["install", "-y", "postfix", "postfix-mysql"]).await?;

        shell::exec("systemctl", &["enable", POSTFIX_SERVICE]).await?;

        info!("Postfix installed successfully");
        Ok(())
    }

    async fn start(&self) -> Result<(), ServiceError> {
        info!("Starting Postfix...");
        shell::exec("systemctl", &["start", POSTFIX_SERVICE]).await?;
        Ok(())
    }

    async fn stop(&self) -> Result<(), ServiceError> {
        info!("Stopping Postfix...");
        shell::exec("systemctl", &["stop", POSTFIX_SERVICE]).await?;
        Ok(())
    }

    async fn restart(&self) -> Result<(), ServiceError> {
        info!("Restarting Postfix...");
        shell::exec("systemctl", &["restart", POSTFIX_SERVICE]).await?;
        Ok(())
    }

    async fn status(&self) -> Result<ServiceStatus, ServiceError> {
        match shell::exec("systemctl", &["is-active", POSTFIX_SERVICE]).await {
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
        Ok(Path::new("/usr/sbin/postfix").exists())
    }

    async fn version(&self) -> Result<String, ServiceError> {
        let output = shell::exec("postfix", &["--version"])
            .await
            .map_err(|_| ServiceError::CommandFailed("postfix version unavailable".into()))?;
        let version = String::from_utf8_lossy(&output.stdout);
        Ok(version.trim().to_string())
    }
}

impl PostfixService {
    /// Configure Postfix for virtual domain hosting.
    /// Sets up virtual mailbox domains, mailboxes, and aliases using hash files.
    /// `policy_port` is read from `[postfix] policy_port` in `panel.toml`.
    pub async fn configure_virtual_hosting(
        &self,
        hostname: &str,
        policy_port: u16,
    ) -> Result<(), ServiceError> {
        // Defense-in-depth: validate hostname at service layer
        crate::utils::validators::validate_domain(hostname)
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;
        info!("Configuring Postfix for virtual hosting...");

        // Create vmail system user for virtual mailbox delivery
        let _ = shell::exec(
            "useradd",
            &[
                "-r",
                "-u",
                VMAIL_UID,
                "-g",
                VMAIL_GID,
                "-d",
                VIRTUAL_MAILBOX_BASE,
                "-s",
                "/usr/sbin/nologin",
                VMAIL_USER,
            ],
        )
        .await;

        // Create mailbox base directory
        shell::exec("mkdir", &["-p", VIRTUAL_MAILBOX_BASE]).await?;
        shell::exec(
            "chown",
            &[
                "-R",
                &format!("{}:{}", VMAIL_USER, VMAIL_USER),
                VIRTUAL_MAILBOX_BASE,
            ],
        )
        .await?;

        // Create empty lookup files
        for file in &[
            VIRTUAL_DOMAINS_FILE,
            VIRTUAL_MAILBOX_FILE,
            VIRTUAL_ALIAS_FILE,
        ] {
            if !Path::new(file).exists() {
                fs::write(file, "")
                    .await
                    .map_err(|e| ServiceError::IoError(e.to_string()))?;
            }
        }

        // Read old main.cf for rollback in case postfix check fails.
        // Distinguish between "not found" (OK during initial install) and a read
        // error that would leave us without a rollback point.
        let old_main_cf = match fs::read_to_string(POSTFIX_MAIN_CF).await {
            Ok(content) => Some(content),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                return Err(ServiceError::IoError(format!(
                    "Failed to backup main.cf before modification: {e}"
                )))
            }
        };

        // Write new main.cf atomically
        let main_cf = generate_main_cf(hostname, policy_port);
        let main_cf_tmp = format!("{}.tmp", POSTFIX_MAIN_CF);
        fs::write(&main_cf_tmp, &main_cf)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;
        fs::rename(&main_cf_tmp, POSTFIX_MAIN_CF)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        // Validate config and rebuild hash maps; roll back main.cf on failure
        if let Err(e) = self.postmap_all().await {
            if let Some(old) = &old_main_cf {
                restore_file(POSTFIX_MAIN_CF, old).await?;
            }
            return Err(e);
        }

        // Reload Postfix
        self.restart().await?;

        info!("Postfix virtual hosting configured");
        Ok(())
    }

    /// Add a virtual domain.
    pub async fn add_domain(&self, domain: &str) -> Result<(), ServiceError> {
        // Defense-in-depth: validate domain at service layer
        crate::utils::validators::validate_domain(domain)
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;

        info!("Adding virtual domain: {}", domain);

        let _lock = super::filelock::FileLock::exclusive(VIRTUAL_DOMAINS_FILE)?;

        let old_content = fs::read_to_string(VIRTUAL_DOMAINS_FILE)
            .await
            .unwrap_or_default();

        let entry = format!("{} OK\n", domain);
        let wrote = if !old_content.contains(&entry) {
            let new_content = format!("{}{}", old_content, entry);
            let domains_tmp = format!("{}.tmp", VIRTUAL_DOMAINS_FILE);
            fs::write(&domains_tmp, &new_content)
                .await
                .map_err(|e| ServiceError::IoError(e.to_string()))?;
            fs::rename(&domains_tmp, VIRTUAL_DOMAINS_FILE)
                .await
                .map_err(|e| ServiceError::IoError(e.to_string()))?;
            true
        } else {
            false
        };

        if let Err(e) = self.postmap(VIRTUAL_DOMAINS_FILE).await {
            if wrote {
                restore_file(VIRTUAL_DOMAINS_FILE, &old_content).await?;
            }
            return Err(e);
        }
        Ok(())
    }

    /// Remove a virtual domain.
    pub async fn remove_domain(&self, domain: &str) -> Result<(), ServiceError> {
        crate::utils::validators::validate_domain(domain)
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;

        info!("Removing virtual domain: {}", domain);

        let _lock = super::filelock::FileLock::exclusive(VIRTUAL_DOMAINS_FILE)?;

        // Snapshot all three map files before any write for atomic rollback
        let old_domains = fs::read_to_string(VIRTUAL_DOMAINS_FILE)
            .await
            .unwrap_or_default();
        let old_mailboxes = fs::read_to_string(VIRTUAL_MAILBOX_FILE)
            .await
            .unwrap_or_default();
        let old_aliases = fs::read_to_string(VIRTUAL_ALIAS_FILE)
            .await
            .unwrap_or_default();

        let new_domains: String = old_domains
            .lines()
            .filter(|line| !line.starts_with(&format!("{domain} ")))
            .map(|line| format!("{line}\n"))
            .collect();

        let domains_tmp = format!("{}.tmp", VIRTUAL_DOMAINS_FILE);
        fs::write(&domains_tmp, &new_domains)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;
        fs::rename(&domains_tmp, VIRTUAL_DOMAINS_FILE)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        // Also remove all mailboxes and aliases for this domain
        self.remove_domain_mailboxes(domain).await?;
        self.remove_domain_aliases(domain).await?;

        // Validate and reload; roll back all three files if check fails
        if let Err(e) = self.postmap_all().await {
            restore_file(VIRTUAL_DOMAINS_FILE, &old_domains).await?;
            restore_file(VIRTUAL_MAILBOX_FILE, &old_mailboxes).await?;
            restore_file(VIRTUAL_ALIAS_FILE, &old_aliases).await?;
            return Err(e);
        }
        Ok(())
    }

    /// Add a virtual mailbox.
    pub async fn add_mailbox(&self, email: &str, domain: &str) -> Result<(), ServiceError> {
        // Defense-in-depth: validate inputs to prevent path traversal in maildir paths
        crate::utils::validators::validate_email(email)
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;
        crate::utils::validators::validate_domain(domain)
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;

        info!("Adding virtual mailbox: {}", email);

        let _lock = super::filelock::FileLock::exclusive(VIRTUAL_MAILBOX_FILE)?;

        let old_content = fs::read_to_string(VIRTUAL_MAILBOX_FILE)
            .await
            .unwrap_or_default();

        let maildir_path = format!("{}/{}/{}/\n", VIRTUAL_MAILBOX_BASE, domain, email);
        let entry = format!("{} {}", email, maildir_path);
        // SEC-B2-07: use a line-anchored check so that 'xa@domain.com' does not
        // silently block 'a@domain.com' via substring match.
        let wrote = if !old_content
            .lines()
            .any(|l| l.starts_with(&format!("{email} ")))
        {
            let new_content = format!("{}{}", old_content, entry);
            let mailbox_tmp = format!("{}.tmp", VIRTUAL_MAILBOX_FILE);
            fs::write(&mailbox_tmp, &new_content)
                .await
                .map_err(|e| ServiceError::IoError(e.to_string()))?;
            fs::rename(&mailbox_tmp, VIRTUAL_MAILBOX_FILE)
                .await
                .map_err(|e| ServiceError::IoError(e.to_string()))?;
            true
        } else {
            false
        };

        // Create the Maildir structure
        let maildir = format!("{}/{}/{}", VIRTUAL_MAILBOX_BASE, domain, email);
        shell::exec("mkdir", &["-p", &format!("{}/cur", maildir)]).await?;
        shell::exec("mkdir", &["-p", &format!("{}/new", maildir)]).await?;
        shell::exec("mkdir", &["-p", &format!("{}/tmp", maildir)]).await?;
        shell::exec(
            "chown",
            &["-R", &format!("{}:{}", VMAIL_USER, VMAIL_USER), &maildir],
        )
        .await?;

        if let Err(e) = self.postmap(VIRTUAL_MAILBOX_FILE).await {
            if wrote {
                restore_file(VIRTUAL_MAILBOX_FILE, &old_content).await?;
            }
            return Err(e);
        }
        Ok(())
    }

    /// Remove a virtual mailbox.
    pub async fn remove_mailbox(&self, email: &str) -> Result<(), ServiceError> {
        crate::utils::validators::validate_email(email)
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;

        info!("Removing virtual mailbox: {}", email);

        let _lock = super::filelock::FileLock::exclusive(VIRTUAL_MAILBOX_FILE)?;

        let old_content = fs::read_to_string(VIRTUAL_MAILBOX_FILE)
            .await
            .unwrap_or_default();

        let new_content: String = old_content
            .lines()
            .filter(|line| !line.starts_with(&format!("{email} ")))
            .map(|line| format!("{line}\n"))
            .collect();

        let mailbox_tmp = format!("{}.tmp", VIRTUAL_MAILBOX_FILE);
        fs::write(&mailbox_tmp, &new_content)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;
        fs::rename(&mailbox_tmp, VIRTUAL_MAILBOX_FILE)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        if let Err(e) = self.postmap(VIRTUAL_MAILBOX_FILE).await {
            restore_file(VIRTUAL_MAILBOX_FILE, &old_content).await?;
            return Err(e);
        }
        Ok(())
    }

    /// Add a virtual alias (email forwarding).
    pub async fn add_alias(&self, source: &str, destination: &str) -> Result<(), ServiceError> {
        crate::utils::validators::validate_email(source)
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;
        crate::utils::validators::validate_email(destination)
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;

        info!("Adding virtual alias: {} -> {}", source, destination);

        let _lock = super::filelock::FileLock::exclusive(VIRTUAL_ALIAS_FILE)?;

        let old_content = fs::read_to_string(VIRTUAL_ALIAS_FILE)
            .await
            .unwrap_or_default();

        let entry = format!("{} {}\n", source, destination);
        let wrote = if !old_content.contains(&entry) {
            let new_content = format!("{}{}", old_content, entry);
            let alias_tmp = format!("{}.tmp", VIRTUAL_ALIAS_FILE);
            fs::write(&alias_tmp, &new_content)
                .await
                .map_err(|e| ServiceError::IoError(e.to_string()))?;
            fs::rename(&alias_tmp, VIRTUAL_ALIAS_FILE)
                .await
                .map_err(|e| ServiceError::IoError(e.to_string()))?;
            true
        } else {
            false
        };

        if let Err(e) = self.postmap(VIRTUAL_ALIAS_FILE).await {
            if wrote {
                restore_file(VIRTUAL_ALIAS_FILE, &old_content).await?;
            }
            return Err(e);
        }
        Ok(())
    }

    /// Remove a virtual alias.
    pub async fn remove_alias(&self, source: &str) -> Result<(), ServiceError> {
        // Defense-in-depth: validate email at service layer
        crate::utils::validators::validate_email(source)
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;

        let _lock = super::filelock::FileLock::exclusive(VIRTUAL_ALIAS_FILE)?;

        let old_content = fs::read_to_string(VIRTUAL_ALIAS_FILE)
            .await
            .unwrap_or_default();

        let new_content: String = old_content
            .lines()
            .filter(|line| !line.starts_with(&format!("{source} ")))
            .map(|line| format!("{line}\n"))
            .collect();

        let alias_tmp = format!("{}.tmp", VIRTUAL_ALIAS_FILE);
        fs::write(&alias_tmp, &new_content)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;
        fs::rename(&alias_tmp, VIRTUAL_ALIAS_FILE)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        if let Err(e) = self.postmap(VIRTUAL_ALIAS_FILE).await {
            restore_file(VIRTUAL_ALIAS_FILE, &old_content).await?;
            return Err(e);
        }
        Ok(())
    }

    /// Run `postfix check` then `postfix reload`. Delegates to the module-level
    /// helper so the same logic is used by both single-file and bulk reloads.
    async fn postmap(&self, _file: &str) -> Result<(), ServiceError> {
        postfix_check_and_reload().await
    }

    /// Validate all Postfix maps and reload the daemon.
    async fn postmap_all(&self) -> Result<(), ServiceError> {
        postfix_check_and_reload().await
    }

    /// Remove all mailboxes for a domain.
    async fn remove_domain_mailboxes(&self, domain: &str) -> Result<(), ServiceError> {
        // File lock prevents TOCTOU race on concurrent mailbox map updates
        let _lock = super::filelock::FileLock::exclusive(VIRTUAL_MAILBOX_FILE)?;
        let content = fs::read_to_string(VIRTUAL_MAILBOX_FILE)
            .await
            .unwrap_or_default();

        let new_content: String = content
            .lines()
            .filter(|line| !line.contains(&format!("@{}", domain)))
            .map(|line| format!("{}\n", line))
            .collect();

        let mbox_tmp = format!("{}.tmp", VIRTUAL_MAILBOX_FILE);
        fs::write(&mbox_tmp, &new_content)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;
        fs::rename(&mbox_tmp, VIRTUAL_MAILBOX_FILE)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        Ok(())
    }

    /// Remove all aliases for a domain.
    async fn remove_domain_aliases(&self, domain: &str) -> Result<(), ServiceError> {
        // File lock prevents TOCTOU race on concurrent alias map updates
        let _lock = super::filelock::FileLock::exclusive(VIRTUAL_ALIAS_FILE)?;
        let content = fs::read_to_string(VIRTUAL_ALIAS_FILE)
            .await
            .unwrap_or_default();

        let new_content: String = content
            .lines()
            .filter(|line| !line.contains(&format!("@{}", domain)))
            .map(|line| format!("{}\n", line))
            .collect();

        let alias_tmp = format!("{}.tmp", VIRTUAL_ALIAS_FILE);
        fs::write(&alias_tmp, &new_content)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;
        fs::rename(&alias_tmp, VIRTUAL_ALIAS_FILE)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        Ok(())
    }
}

/// Generate Postfix main.cf for virtual domain hosting.
fn generate_main_cf(hostname: &str, policy_port: u16) -> String {
    format!(
        r#"# Postfix main.cf - Managed by Hosting Control Panel
# Do not edit manually — changes will be overwritten.

# General
smtpd_banner = $myhostname ESMTP
biff = no
append_dot_mydomain = no
readme_directory = no
compatibility_level = 3.6

# Hostname
myhostname = {hostname}
mydomain = {hostname}
myorigin = $mydomain
mydestination = localhost

# Network
inet_interfaces = all
inet_protocols = ipv4

# Virtual domains and mailboxes
virtual_mailbox_domains = hash:{vdomains}
virtual_mailbox_maps = hash:{vmailboxes}
virtual_alias_maps = hash:{valiases}
virtual_mailbox_base = {vmailbase}
virtual_minimum_uid = 100
virtual_uid_maps = static:{vuid}
virtual_gid_maps = static:{vgid}

# TLS (incoming SMTP)
smtpd_tls_security_level = may
smtpd_tls_cert_file = /etc/ssl/certs/ssl-cert-snakeoil.pem
smtpd_tls_key_file = /etc/ssl/private/ssl-cert-snakeoil.key
smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1

# TLS (outgoing SMTP)
smtp_tls_security_level = may
smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1

# SASL Authentication (via Dovecot)
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes
smtpd_sasl_security_options = noanonymous
smtpd_sasl_local_domain = $myhostname

# Restrictions
smtpd_helo_required = yes
smtpd_recipient_restrictions =
    check_policy_service inet:127.0.0.1:{policy_port},
    permit_sasl_authenticated,
    permit_mynetworks,
    reject_unauth_destination,
    reject_invalid_hostname,
    reject_non_fqdn_hostname,
    reject_non_fqdn_sender,
    reject_non_fqdn_recipient,
    reject_unknown_sender_domain,
    reject_unknown_recipient_domain,
    reject_rbl_client zen.spamhaus.org

# Mailbox size limits
mailbox_size_limit = 0
message_size_limit = 52428800
virtual_mailbox_limit = 0

# Milter for DKIM signing (optional, configure later)
# milter_default_action = accept
# milter_protocol = 6
# smtpd_milters = inet:localhost:8891
# non_smtpd_milters = $smtpd_milters
"#,
        hostname = hostname,
        vdomains = VIRTUAL_DOMAINS_FILE,
        vmailboxes = VIRTUAL_MAILBOX_FILE,
        valiases = VIRTUAL_ALIAS_FILE,
        vmailbase = VIRTUAL_MAILBOX_BASE,
        vuid = VMAIL_UID,
        vgid = VMAIL_GID,
        policy_port = policy_port,
    )
}

impl PostfixService {
    /// Update Postfix main.cf to use the provided TLS certificate and key.
    pub async fn update_tls_cert(
        &self,
        cert_path: &str,
        key_path: &str,
    ) -> Result<(), super::ServiceError> {
        // Defense-in-depth: reject paths containing newlines, null bytes, or ".."
        // traversal sequences, and require paths to be within known cert directories.
        if cert_path.contains('\n') || cert_path.contains('\0') || cert_path.contains("..") {
            return Err(super::ServiceError::CommandFailed(
                "Invalid cert path".into(),
            ));
        }
        if key_path.contains('\n') || key_path.contains('\0') || key_path.contains("..") {
            return Err(super::ServiceError::CommandFailed(
                "Invalid key path".into(),
            ));
        }
        for (label, path) in &[("cert_path", cert_path), ("key_path", key_path)] {
            let allowed = path.starts_with("/etc/letsencrypt/")
                || path.starts_with("/etc/ssl/panel/")
                || path.starts_with("/etc/ssl/");
            if !allowed {
                return Err(super::ServiceError::CommandFailed(format!(
                    "{label} is outside permitted certificate directories"
                )));
            }
        }
        // File lock prevents TOCTOU race on concurrent main.cf updates
        let _lock = super::filelock::FileLock::exclusive(POSTFIX_MAIN_CF)?;
        let old_main_cf = tokio::fs::read_to_string(POSTFIX_MAIN_CF)
            .await
            .unwrap_or_default();

        // Update or append TLS cert lines.
        let mut updated = String::new();
        let mut cert_set = false;
        let mut key_set = false;
        for line in old_main_cf.lines() {
            if line.starts_with("smtpd_tls_cert_file") {
                updated.push_str(&format!("smtpd_tls_cert_file = {}\n", cert_path));
                cert_set = true;
            } else if line.starts_with("smtpd_tls_key_file") {
                updated.push_str(&format!("smtpd_tls_key_file = {}\n", key_path));
                key_set = true;
            } else {
                updated.push_str(line);
                updated.push('\n');
            }
        }
        if !cert_set {
            updated.push_str(&format!("smtpd_tls_cert_file = {}\n", cert_path));
        }
        if !key_set {
            updated.push_str(&format!("smtpd_tls_key_file = {}\n", key_path));
        }

        let main_cf_tmp = format!("{}.tmp", POSTFIX_MAIN_CF);
        tokio::fs::write(&main_cf_tmp, &updated)
            .await
            .map_err(|e| super::ServiceError::IoError(e.to_string()))?;
        tokio::fs::rename(&main_cf_tmp, POSTFIX_MAIN_CF)
            .await
            .map_err(|e| super::ServiceError::IoError(e.to_string()))?;

        if let Err(e) = postfix_check_and_reload().await {
            restore_file(POSTFIX_MAIN_CF, &old_main_cf).await?;
            return Err(e);
        }
        Ok(())
    }

    // ─── Catch-all ──────────────────────────────────────────────────────────

    /// Set or clear the catch-all alias for a domain.
    /// Postfix syntax: `@domain.com  destination@example.com`
    /// Pass `None` to remove the catch-all.
    pub async fn set_catch_all(
        &self,
        domain: &str,
        destination: Option<&str>,
    ) -> Result<(), super::ServiceError> {
        let _lock = super::filelock::FileLock::exclusive(VIRTUAL_ALIAS_FILE)?;
        let old_content = tokio::fs::read_to_string(VIRTUAL_ALIAS_FILE)
            .await
            .unwrap_or_default();

        let catch_all_prefix = format!("@{}", domain);

        // Remove any existing catch-all for this domain.
        let mut new_content: String = old_content
            .lines()
            .filter(|l| !l.starts_with(&catch_all_prefix))
            .map(|l| format!("{}\n", l))
            .collect();

        if let Some(dest) = destination {
            new_content.push_str(&format!("{} {}\n", catch_all_prefix, dest));
        }

        let alias_tmp = format!("{}.tmp", VIRTUAL_ALIAS_FILE);
        tokio::fs::write(&alias_tmp, &new_content)
            .await
            .map_err(|e| super::ServiceError::IoError(e.to_string()))?;
        tokio::fs::rename(&alias_tmp, VIRTUAL_ALIAS_FILE)
            .await
            .map_err(|e| super::ServiceError::IoError(e.to_string()))?;

        if let Err(e) = self.postmap_all().await {
            restore_file(VIRTUAL_ALIAS_FILE, &old_content).await?;
            return Err(e);
        }
        Ok(())
    }

    // ─── Plus-addressing ────────────────────────────────────────────────────

    /// Enable or disable `recipient_delimiter = +` in Postfix main.cf.
    pub async fn set_plus_addressing(&self, enabled: bool) -> Result<(), super::ServiceError> {
        let _lock = super::filelock::FileLock::exclusive(POSTFIX_MAIN_CF)?;
        let old_main_cf = tokio::fs::read_to_string(POSTFIX_MAIN_CF)
            .await
            .unwrap_or_default();

        let mut updated = String::new();
        let mut found = false;
        for line in old_main_cf.lines() {
            if line.starts_with("recipient_delimiter") {
                found = true;
                if enabled {
                    updated.push_str("recipient_delimiter = +\n");
                }
                // if disabled, just drop the line
            } else {
                updated.push_str(line);
                updated.push('\n');
            }
        }
        if !found && enabled {
            updated.push_str("recipient_delimiter = +\n");
        }

        let main_cf_tmp = format!("{}.tmp", POSTFIX_MAIN_CF);
        tokio::fs::write(&main_cf_tmp, &updated)
            .await
            .map_err(|e| super::ServiceError::IoError(e.to_string()))?;
        tokio::fs::rename(&main_cf_tmp, POSTFIX_MAIN_CF)
            .await
            .map_err(|e| super::ServiceError::IoError(e.to_string()))?;

        if let Err(e) = self.postmap_all().await {
            restore_file(POSTFIX_MAIN_CF, &old_main_cf).await?;
            return Err(e);
        }
        Ok(())
    }

    // ─── Regex forwarders ───────────────────────────────────────────────────

    const VIRTUAL_REGEX_FILE: &'static str = "/etc/postfix/virtual_regex";

    /// Rebuild the Postfix regexp virtual-alias map from all active regex forwarders
    /// and ensure main.cf includes `regexp:/etc/postfix/virtual_regex` in
    /// `virtual_alias_maps`.
    pub async fn rebuild_regex_map(
        &self,
        forwarders: &[(String, String)], // (pattern, forward_to)
    ) -> Result<(), super::ServiceError> {
        // Write regexp file atomically.
        let mut content = String::new();
        for (pattern, dest) in forwarders {
            // Defense-in-depth: skip any pattern that contains Postfix regexp
            // delimiters or line-injection characters to prevent map corruption.
            if pattern.contains('/')
                || pattern.contains('\n')
                || pattern.contains('\r')
                || pattern.contains('\0')
            {
                continue;
            }
            // SEC-33-04: also guard the destination for newlines to prevent
            // line-injection into the map file from corrupted DB records.
            if dest.contains('\n') || dest.contains('\r') || dest.contains('\0') {
                continue;
            }
            content.push_str(&format!("/{}/  {}\n", pattern, dest));
        }
        // Snapshot regex file for rollback (may not exist yet on first call)
        let old_regex = tokio::fs::read_to_string(Self::VIRTUAL_REGEX_FILE)
            .await
            .unwrap_or_default();

        let regex_tmp = format!("{}.tmp", Self::VIRTUAL_REGEX_FILE);
        tokio::fs::write(&regex_tmp, &content)
            .await
            .map_err(|e| super::ServiceError::IoError(e.to_string()))?;
        tokio::fs::rename(&regex_tmp, Self::VIRTUAL_REGEX_FILE)
            .await
            .map_err(|e| super::ServiceError::IoError(e.to_string()))?;

        // Ensure main.cf references the regexp map (with file lock).
        let _lock = super::filelock::FileLock::exclusive(POSTFIX_MAIN_CF)?;
        let old_main_cf = tokio::fs::read_to_string(POSTFIX_MAIN_CF)
            .await
            .unwrap_or_default();

        let regexp_ref = format!("regexp:{}", Self::VIRTUAL_REGEX_FILE);
        let mut updated = String::new();
        for line in old_main_cf.lines() {
            if line.starts_with("virtual_alias_maps") && !line.contains("regexp:") {
                // append regexp map reference
                updated.push_str(line.trim_end());
                updated.push_str(&format!(", {}\n", regexp_ref));
            } else {
                updated.push_str(line);
                updated.push('\n');
            }
        }

        let main_cf_tmp = format!("{}.tmp", POSTFIX_MAIN_CF);
        tokio::fs::write(&main_cf_tmp, &updated)
            .await
            .map_err(|e| super::ServiceError::IoError(e.to_string()))?;
        tokio::fs::rename(&main_cf_tmp, POSTFIX_MAIN_CF)
            .await
            .map_err(|e| super::ServiceError::IoError(e.to_string()))?;

        if let Err(e) = self.postmap_all().await {
            restore_file(Self::VIRTUAL_REGEX_FILE, &old_regex).await?;
            restore_file(POSTFIX_MAIN_CF, &old_main_cf).await?;
            return Err(e);
        }
        Ok(())
    }

    // ─── DKIM milter ────────────────────────────────────────────────────────

    /// Enable the OpenDKIM milter in main.cf.
    /// Idempotent — only adds the lines if they are not already present.
    pub async fn enable_dkim_milter(&self) -> Result<(), super::ServiceError> {
        // Lock main.cf before read-modify-write to prevent TOCTOU races
        // with concurrent Postfix configuration operations.
        let _lock = super::filelock::FileLock::exclusive(POSTFIX_MAIN_CF)?;
        let old_main_cf = tokio::fs::read_to_string(POSTFIX_MAIN_CF)
            .await
            .unwrap_or_default();

        if old_main_cf.contains("smtpd_milters") && !old_main_cf.contains("# smtpd_milters") {
            return Ok(()); // already configured
        }

        // Remove commented-out milter lines, then append active ones.
        let mut updated: String = old_main_cf
            .lines()
            .filter(|l| {
                !l.trim_start().starts_with("# milter")
                    && !l.trim_start().starts_with("# smtpd_milters")
                    && !l.trim_start().starts_with("# non_smtpd_milters")
            })
            .map(|l| format!("{}\n", l))
            .collect();

        updated.push_str("\n# DKIM signing via OpenDKIM\n");
        updated.push_str("milter_default_action = accept\n");
        updated.push_str("milter_protocol = 6\n");
        updated.push_str("smtpd_milters = inet:localhost:8891\n");
        updated.push_str("non_smtpd_milters = $smtpd_milters\n");

        let main_cf_tmp = format!("{}.tmp", POSTFIX_MAIN_CF);
        tokio::fs::write(&main_cf_tmp, &updated)
            .await
            .map_err(|e| super::ServiceError::IoError(e.to_string()))?;
        tokio::fs::rename(&main_cf_tmp, POSTFIX_MAIN_CF)
            .await
            .map_err(|e| super::ServiceError::IoError(e.to_string()))?;

        if let Err(e) = self.postmap_all().await {
            restore_file(POSTFIX_MAIN_CF, &old_main_cf).await?;
            return Err(e);
        }
        Ok(())
    }
}

/// Run `postfix check` to validate configuration, then `postfix reload` to apply it.
/// Returns an error (with stderr output) if either step fails — callers use this
/// to decide whether to roll back config files.
async fn postfix_check_and_reload() -> Result<(), ServiceError> {
    let check = shell::exec("postfix", &["check"])
        .await
        .map_err(|e| ServiceError::CommandFailed(format!("postfix check failed: {e}")))?;
    if !check.status.success() {
        let stderr = String::from_utf8_lossy(&check.stderr);
        return Err(ServiceError::CommandFailed(format!(
            "postfix check failed: {}",
            stderr.trim()
        )));
    }
    let reload = shell::exec("postfix", &["reload"])
        .await
        .map_err(|e| ServiceError::CommandFailed(format!("postfix reload failed: {e}")))?;
    if !reload.status.success() {
        let stderr = String::from_utf8_lossy(&reload.stderr);
        return Err(ServiceError::CommandFailed(format!(
            "postfix reload failed: {}",
            stderr.trim()
        )));
    }
    Ok(())
}

/// Atomically restore a file to `content` using a tmp-then-rename strategy.
/// Called by provisioning functions on `postfix check` failure to undo their writes.
async fn restore_file(path: &str, content: &str) -> Result<(), ServiceError> {
    let tmp = format!("{path}.tmp");
    fs::write(&tmp, content)
        .await
        .map_err(|e| ServiceError::IoError(e.to_string()))?;
    fs::rename(&tmp, path)
        .await
        .map_err(|e| ServiceError::IoError(e.to_string()))?;
    Ok(())
}
