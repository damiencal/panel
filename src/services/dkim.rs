/// OpenDKIM signing key management.
///
/// Generates 2048-bit RSA key pairs per domain, writes them to
/// `/etc/opendkim/keys/{domain}/{selector}.private`, configures
/// the signing-table and key-table, and enables the milter in Postfix.
use super::{shell, ServiceError};
use tokio::fs;
use tracing::info;

const OPENDKIM_CONF: &str = "/etc/opendkim.conf";
const OPENDKIM_KEYS_DIR: &str = "/etc/opendkim/keys";
const OPENDKIM_SIGNING_TABLE: &str = "/etc/opendkim/signing-table";
const OPENDKIM_KEY_TABLE: &str = "/etc/opendkim/key-table";
const OPENDKIM_TRUSTED_HOSTS: &str = "/etc/opendkim/trusted-hosts";

pub struct DkimService;

impl DkimService {
    /// Ensure OpenDKIM is installed and the base configuration exists.
    pub async fn ensure_installed(&self) -> Result<(), ServiceError> {
        if !std::path::Path::new("/usr/sbin/opendkim").exists() {
            shell::exec("apt-get", &["install", "-y", "opendkim", "opendkim-tools"]).await?;
        }

        // Create key directory.
        shell::exec("mkdir", &["-p", OPENDKIM_KEYS_DIR]).await?;

        if !std::path::Path::new(OPENDKIM_CONF).exists() {
            self.write_base_conf().await?;
        }

        if !std::path::Path::new(OPENDKIM_SIGNING_TABLE).exists() {
            fs::write(OPENDKIM_SIGNING_TABLE, "")
                .await
                .map_err(|e| ServiceError::IoError(e.to_string()))?;
        }
        if !std::path::Path::new(OPENDKIM_KEY_TABLE).exists() {
            fs::write(OPENDKIM_KEY_TABLE, "")
                .await
                .map_err(|e| ServiceError::IoError(e.to_string()))?;
        }
        if !std::path::Path::new(OPENDKIM_TRUSTED_HOSTS).exists() {
            fs::write(OPENDKIM_TRUSTED_HOSTS, "127.0.0.1\nlocalhost\n::1\n")
                .await
                .map_err(|e| ServiceError::IoError(e.to_string()))?;
        }

        shell::exec("systemctl", &["enable", "opendkim"]).await.ok();

        Ok(())
    }

    /// Generate a 2048-bit RSA DKIM key pair for `domain` using `selector`.
    /// Returns the DNS TXT record value (the `v=DKIM1; k=rsa; p=…` string).
    pub async fn generate_key(&self, domain: &str, selector: &str) -> Result<String, ServiceError> {
        // Defense-in-depth: validate inputs at service layer
        crate::utils::validators::validate_domain(domain)
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;
        if selector.is_empty()
            || selector.len() > 63
            || !selector.chars().all(|c| c.is_alphanumeric() || c == '-')
        {
            return Err(ServiceError::CommandFailed(
                "Invalid DKIM selector: must be alphanumeric/hyphen, max 63 chars".into(),
            ));
        }
        info!(
            "Generating DKIM key for domain {} selector {}",
            domain, selector
        );

        self.ensure_installed().await?;

        let key_dir = format!("{}/{}", OPENDKIM_KEYS_DIR, domain);
        shell::exec("mkdir", &["-p", &key_dir]).await?;

        // opendkim-genkey writes {selector}.private and {selector}.txt into key_dir.
        shell::exec(
            "opendkim-genkey",
            &[
                "-b", "2048", "-d", domain, "-D", &key_dir, "-s", selector, "-v",
            ],
        )
        .await?;

        // Secure the private key.
        let private_key_path = format!("{}/{}.private", key_dir, selector);
        shell::exec("chown", &["opendkim:opendkim", &private_key_path])
            .await
            .ok();
        shell::exec("chmod", &["600", &private_key_path]).await.ok();

        // Read the DNS TXT record.
        let txt_path = format!("{}/{}.txt", key_dir, selector);
        let txt_raw = fs::read_to_string(&txt_path)
            .await
            .map_err(|e| ServiceError::IoError(format!("Cannot read DKIM TXT: {}", e)))?;

        // The .txt file from opendkim-genkey looks like:
        //   default._domainkey…  IN  TXT  ( "v=DKIM1; k=rsa; " "p=MII…" )
        // Extract the bare TXT value we need to publish.
        let public_key_dns = parse_dkim_txt_record(&txt_raw);

        // Update signing-table and key-table.
        self.add_to_signing_table(domain, selector).await?;
        self.add_to_key_table(domain, selector, &private_key_path)
            .await?;

        // Restart OpenDKIM.
        shell::exec("systemctl", &["restart", "opendkim"])
            .await
            .ok();

        Ok(public_key_dns)
    }

    /// Remove a domain's DKIM configuration.
    pub async fn delete_key(&self, domain: &str, selector: &str) -> Result<(), ServiceError> {
        // Defense-in-depth: validate inputs at service layer
        crate::utils::validators::validate_domain(domain)
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;
        if selector.is_empty()
            || selector.len() > 63
            || !selector.chars().all(|c| c.is_alphanumeric() || c == '-')
        {
            return Err(ServiceError::CommandFailed(
                "Invalid DKIM selector: must be alphanumeric/hyphen, max 63 chars".into(),
            ));
        }
        self.remove_from_signing_table(domain).await?;
        self.remove_from_key_table(domain, selector).await?;

        // Delete key files.
        let key_dir = format!("{}/{}", OPENDKIM_KEYS_DIR, domain);
        let _ = fs::remove_dir_all(&key_dir).await;

        shell::exec("systemctl", &["restart", "opendkim"])
            .await
            .ok();
        Ok(())
    }

    // ─── Internal helpers ────────────────────────────────────────────────────

    async fn write_base_conf(&self) -> Result<(), ServiceError> {
        let conf = r#"# OpenDKIM configuration — managed by hosting panel
Syslog              yes
UMask               002
Canonicalization    relaxed/relaxed
Mode                sv
SubDomains          no
AutoRestart         yes
AutoRestartRate     10/1h
Background          yes
DNSTimeout          5
SignatureAlgorithm  rsa-sha256

KeyTable            /etc/opendkim/key-table
SigningTable        refile:/etc/opendkim/signing-table
InternalHosts       refile:/etc/opendkim/trusted-hosts

Socket              inet:8891@localhost
PidFile             /run/opendkim/opendkim.pid
UserID              opendkim
"#;
        fs::write(OPENDKIM_CONF, conf)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))
    }

    async fn add_to_signing_table(&self, domain: &str, selector: &str) -> Result<(), ServiceError> {
        // File lock prevents TOCTOU race on concurrent signing-table updates
        let _lock = super::filelock::FileLock::exclusive(OPENDKIM_SIGNING_TABLE)?;
        let content = fs::read_to_string(OPENDKIM_SIGNING_TABLE)
            .await
            .unwrap_or_default();

        // Entry format: *@domain  selector._domainkey.domain
        let key_id = format!("{}._domainkey.{}", selector, domain);
        let entry = format!("*@{}  {}\n", domain, key_id);

        let mut new_content: String = content
            .lines()
            .filter(|l| !l.contains(&format!("@{}", domain)))
            .map(|l| format!("{}\n", l))
            .collect();
        new_content.push_str(&entry);

        fs::write(OPENDKIM_SIGNING_TABLE, new_content)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))
    }

    async fn remove_from_signing_table(&self, domain: &str) -> Result<(), ServiceError> {
        // File lock prevents TOCTOU race on concurrent signing-table updates
        let _lock = super::filelock::FileLock::exclusive(OPENDKIM_SIGNING_TABLE)?;
        let content = fs::read_to_string(OPENDKIM_SIGNING_TABLE)
            .await
            .unwrap_or_default();

        let new_content: String = content
            .lines()
            .filter(|l| !l.contains(&format!("@{}", domain)))
            .map(|l| format!("{}\n", l))
            .collect();

        fs::write(OPENDKIM_SIGNING_TABLE, new_content)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))
    }

    async fn add_to_key_table(
        &self,
        domain: &str,
        selector: &str,
        private_key_path: &str,
    ) -> Result<(), ServiceError> {
        // File lock prevents TOCTOU race on concurrent key-table updates
        let _lock = super::filelock::FileLock::exclusive(OPENDKIM_KEY_TABLE)?;
        let content = fs::read_to_string(OPENDKIM_KEY_TABLE)
            .await
            .unwrap_or_default();

        // Entry format: selector._domainkey.domain  domain:selector:/path/to/private
        let key_id = format!("{}._domainkey.{}", selector, domain);
        let entry = format!("{}  {}:{}:{}\n", key_id, domain, selector, private_key_path);

        let mut new_content: String = content
            .lines()
            .filter(|l| !l.contains(domain))
            .map(|l| format!("{}\n", l))
            .collect();
        new_content.push_str(&entry);

        fs::write(OPENDKIM_KEY_TABLE, new_content)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))
    }

    async fn remove_from_key_table(
        &self,
        domain: &str,
        selector: &str,
    ) -> Result<(), ServiceError> {
        // File lock prevents TOCTOU race on concurrent key-table updates
        let _lock = super::filelock::FileLock::exclusive(OPENDKIM_KEY_TABLE)?;
        let content = fs::read_to_string(OPENDKIM_KEY_TABLE)
            .await
            .unwrap_or_default();

        let key_id = format!("{}._domainkey.{}", selector, domain);
        let new_content: String = content
            .lines()
            .filter(|l| !l.starts_with(&key_id))
            .map(|l| format!("{}\n", l))
            .collect();

        fs::write(OPENDKIM_KEY_TABLE, new_content)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))
    }
}

/// Parse the raw output of `opendkim-genkey` .txt file into a single DNS TXT value.
///
/// The file looks like:
/// ```text
/// default._domainkey  IN  TXT ( "v=DKIM1; k=rsa; "
///           "p=MIIBIjANBgk…" )
/// ```
/// We join all quoted segments into one `v=DKIM1; k=rsa; p=…` string.
fn parse_dkim_txt_record(raw: &str) -> String {
    let mut parts = Vec::new();
    for segment in raw.split('"') {
        let s = segment.trim();
        if s.starts_with("v=") || s.starts_with("k=") || s.starts_with("p=") || s.starts_with("t=")
        {
            parts.push(s.to_string());
        }
    }
    if parts.is_empty() {
        // Fallback: return the whole thing stripped of comment chars
        raw.lines()
            .map(|l| l.trim())
            .filter(|l| !l.starts_with(';') && !l.is_empty())
            .collect::<Vec<_>>()
            .join(" ")
    } else {
        parts.join("")
    }
}
