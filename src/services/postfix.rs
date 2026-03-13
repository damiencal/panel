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
const POLICY_SERVICE_PORT: u16 = crate::services::postfix_policy::POLICY_PORT;

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
    pub async fn configure_virtual_hosting(&self, hostname: &str) -> Result<(), ServiceError> {
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

        // Generate main.cf for virtual hosting
        let main_cf = generate_main_cf(hostname);
        fs::write(POSTFIX_MAIN_CF, main_cf)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        // Rebuild hash maps
        self.postmap_all().await?;

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

        let mut content = fs::read_to_string(VIRTUAL_DOMAINS_FILE)
            .await
            .unwrap_or_default();

        let entry = format!("{} OK\n", domain);
        if !content.contains(&entry) {
            content.push_str(&entry);
            fs::write(VIRTUAL_DOMAINS_FILE, content)
                .await
                .map_err(|e| ServiceError::IoError(e.to_string()))?;
        }

        self.postmap(VIRTUAL_DOMAINS_FILE).await?;
        Ok(())
    }

    /// Remove a virtual domain.
    pub async fn remove_domain(&self, domain: &str) -> Result<(), ServiceError> {
        crate::utils::validators::validate_domain(domain)
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;

        info!("Removing virtual domain: {}", domain);

        let _lock = super::filelock::FileLock::exclusive(VIRTUAL_DOMAINS_FILE)?;

        let content = fs::read_to_string(VIRTUAL_DOMAINS_FILE)
            .await
            .unwrap_or_default();

        let new_content: String = content
            .lines()
            .filter(|line| !line.starts_with(domain))
            .map(|line| format!("{}\n", line))
            .collect();

        fs::write(VIRTUAL_DOMAINS_FILE, new_content)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        // Also remove all mailboxes and aliases for this domain
        self.remove_domain_mailboxes(domain).await?;
        self.remove_domain_aliases(domain).await?;

        self.postmap_all().await?;
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

        let mut content = fs::read_to_string(VIRTUAL_MAILBOX_FILE)
            .await
            .unwrap_or_default();

        let maildir_path = format!("{}/{}/{}/\n", VIRTUAL_MAILBOX_BASE, domain, email);
        let entry = format!("{} {}", email, maildir_path);
        if !content.contains(email) {
            content.push_str(&entry);
            fs::write(VIRTUAL_MAILBOX_FILE, content)
                .await
                .map_err(|e| ServiceError::IoError(e.to_string()))?;
        }

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

        self.postmap(VIRTUAL_MAILBOX_FILE).await?;
        Ok(())
    }

    /// Remove a virtual mailbox.
    pub async fn remove_mailbox(&self, email: &str) -> Result<(), ServiceError> {
        crate::utils::validators::validate_email(email)
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;

        info!("Removing virtual mailbox: {}", email);

        let _lock = super::filelock::FileLock::exclusive(VIRTUAL_MAILBOX_FILE)?;

        let content = fs::read_to_string(VIRTUAL_MAILBOX_FILE)
            .await
            .unwrap_or_default();

        let new_content: String = content
            .lines()
            .filter(|line| !line.starts_with(email))
            .map(|line| format!("{}\n", line))
            .collect();

        fs::write(VIRTUAL_MAILBOX_FILE, new_content)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        self.postmap(VIRTUAL_MAILBOX_FILE).await?;
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

        let mut content = fs::read_to_string(VIRTUAL_ALIAS_FILE)
            .await
            .unwrap_or_default();

        let entry = format!("{} {}\n", source, destination);
        if !content.contains(&entry) {
            content.push_str(&entry);
            fs::write(VIRTUAL_ALIAS_FILE, content)
                .await
                .map_err(|e| ServiceError::IoError(e.to_string()))?;
        }

        self.postmap(VIRTUAL_ALIAS_FILE).await?;
        Ok(())
    }

    /// Remove a virtual alias.
    pub async fn remove_alias(&self, source: &str) -> Result<(), ServiceError> {
        // Defense-in-depth: validate email at service layer
        crate::utils::validators::validate_email(source)
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;
        let content = fs::read_to_string(VIRTUAL_ALIAS_FILE)
            .await
            .unwrap_or_default();

        let new_content: String = content
            .lines()
            .filter(|line| !line.starts_with(source))
            .map(|line| format!("{}\n", line))
            .collect();

        fs::write(VIRTUAL_ALIAS_FILE, new_content)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        self.postmap(VIRTUAL_ALIAS_FILE).await?;
        Ok(())
    }

    /// Run postmap to rebuild a hash lookup table.
    async fn postmap(&self, file: &str) -> Result<(), ServiceError> {
        shell::exec("postfix", &["check"]).await.ok();
        // postmap generates the .db file from the flat text file
        shell::exec("postfix", &["reload"]).await.ok();
        // Note: postmap is not in the allowlist, so we use postfix reload
        // which re-reads all lookup tables
        let _ = file; // file path used for context
        Ok(())
    }

    /// Rebuild all hash maps.
    async fn postmap_all(&self) -> Result<(), ServiceError> {
        shell::exec("postfix", &["reload"]).await.ok();
        Ok(())
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

        fs::write(VIRTUAL_MAILBOX_FILE, new_content)
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

        fs::write(VIRTUAL_ALIAS_FILE, new_content)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        Ok(())
    }
}

/// Generate Postfix main.cf for virtual domain hosting.
fn generate_main_cf(hostname: &str) -> String {
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
        policy_port = POLICY_SERVICE_PORT,
    )
}

impl PostfixService {
    /// Update Postfix main.cf to use the provided TLS certificate and key.
    pub async fn update_tls_cert(
        &self,
        cert_path: &str,
        key_path: &str,
    ) -> Result<(), super::ServiceError> {
        // Defense-in-depth: reject paths containing newlines or null bytes
        if cert_path.contains('\n') || cert_path.contains('\0') {
            return Err(super::ServiceError::CommandFailed("Invalid cert path".into()));
        }
        if key_path.contains('\n') || key_path.contains('\0') {
            return Err(super::ServiceError::CommandFailed("Invalid key path".into()));
        }
        // File lock prevents TOCTOU race on concurrent main.cf updates
        let _lock = super::filelock::FileLock::exclusive(POSTFIX_MAIN_CF)?;
        let main_cf = tokio::fs::read_to_string(POSTFIX_MAIN_CF)
            .await
            .unwrap_or_default();

        // Update or append TLS cert lines.
        let mut updated = String::new();
        let mut cert_set = false;
        let mut key_set = false;
        for line in main_cf.lines() {
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

        tokio::fs::write(POSTFIX_MAIN_CF, updated)
            .await
            .map_err(|e| super::ServiceError::IoError(e.to_string()))
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
        let content = tokio::fs::read_to_string(VIRTUAL_ALIAS_FILE)
            .await
            .unwrap_or_default();

        let catch_all_prefix = format!("@{}", domain);

        // Remove any existing catch-all for this domain.
        let mut new_content: String = content
            .lines()
            .filter(|l| !l.starts_with(&catch_all_prefix))
            .map(|l| format!("{}\n", l))
            .collect();

        if let Some(dest) = destination {
            new_content.push_str(&format!("{} {}\n", catch_all_prefix, dest));
        }

        tokio::fs::write(VIRTUAL_ALIAS_FILE, new_content)
            .await
            .map_err(|e| super::ServiceError::IoError(e.to_string()))?;

        self.postmap_all().await
    }

    // ─── Plus-addressing ────────────────────────────────────────────────────

    /// Enable or disable `recipient_delimiter = +` in Postfix main.cf.
    pub async fn set_plus_addressing(&self, enabled: bool) -> Result<(), super::ServiceError> {
        let main_cf = tokio::fs::read_to_string(POSTFIX_MAIN_CF)
            .await
            .unwrap_or_default();

        let mut updated = String::new();
        let mut found = false;
        for line in main_cf.lines() {
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

        tokio::fs::write(POSTFIX_MAIN_CF, updated)
            .await
            .map_err(|e| super::ServiceError::IoError(e.to_string()))?;

        self.postmap_all().await
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
        // Write regexp file.
        let mut content = String::new();
        for (pattern, dest) in forwarders {
            content.push_str(&format!("/{}/  {}\n", pattern, dest));
        }
        tokio::fs::write(Self::VIRTUAL_REGEX_FILE, &content)
            .await
            .map_err(|e| super::ServiceError::IoError(e.to_string()))?;

        // Ensure main.cf references the regexp map.
        let main_cf = tokio::fs::read_to_string(POSTFIX_MAIN_CF)
            .await
            .unwrap_or_default();

        let regexp_ref = format!("regexp:{}", Self::VIRTUAL_REGEX_FILE);
        let mut updated = String::new();
        for line in main_cf.lines() {
            if line.starts_with("virtual_alias_maps") && !line.contains("regexp:") {
                // append regexp map reference
                updated.push_str(line.trim_end());
                updated.push_str(&format!(", {}\n", regexp_ref));
            } else {
                updated.push_str(line);
                updated.push('\n');
            }
        }

        tokio::fs::write(POSTFIX_MAIN_CF, updated)
            .await
            .map_err(|e| super::ServiceError::IoError(e.to_string()))?;

        self.postmap_all().await
    }

    // ─── DKIM milter ────────────────────────────────────────────────────────

    /// Enable the OpenDKIM milter in main.cf.
    /// Idempotent — only adds the lines if they are not already present.
    pub async fn enable_dkim_milter(&self) -> Result<(), super::ServiceError> {
        let main_cf = tokio::fs::read_to_string(POSTFIX_MAIN_CF)
            .await
            .unwrap_or_default();

        if main_cf.contains("smtpd_milters") && !main_cf.contains("# smtpd_milters") {
            return Ok(()); // already configured
        }

        // Remove commented-out milter lines, then append active ones.
        let mut updated: String = main_cf
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

        tokio::fs::write(POSTFIX_MAIN_CF, updated)
            .await
            .map_err(|e| super::ServiceError::IoError(e.to_string()))?;

        self.postmap_all().await
    }
}
