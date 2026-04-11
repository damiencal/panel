/// ModSecurity WAF service management.
/// Supports installation, OWASP / Comodo rule packs, configuration,
/// audit log access, and enable/disable for OpenLiteSpeed.
use super::{shell, ServiceError};
use tokio::fs;
use tracing::info;

// Re-export shared types from models
pub use crate::models::security::{ModSecAuditEntry, ModSecRuleSet, ModSecStatus};

// ─── Paths ───────────────────────────────────────────────────────────────────

const MODSEC_OLS_CONF: &str = "/usr/local/lsws/conf/modsec.conf";
const MODSEC_RULES_DIR: &str = "/etc/modsecurity/rules";
const MODSEC_AUDIT_LOG: &str = "/var/log/modsec_audit.log";
const MODSEC_MAIN_CONF: &str = "/etc/modsecurity/modsecurity.conf";
const OWASP_DIR: &str = "/etc/modsecurity/owasp-crs";
const COMODO_DIR: &str = "/etc/modsecurity/comodo-waf";

// ─── Service ─────────────────────────────────────────────────────────────────

pub struct ModSecurityService;

impl ModSecurityService {
    pub async fn is_installed(&self) -> bool {
        std::path::Path::new(MODSEC_MAIN_CONF).exists()
            || std::path::Path::new("/usr/lib/x86_64-linux-gnu/libmodsecurity.so.3").exists()
            || std::path::Path::new("/usr/lib/aarch64-linux-gnu/libmodsecurity.so.3").exists()
    }

    /// Install ModSecurity and the OpenLiteSpeed ModSecurity connector.
    pub async fn install(&self) -> Result<(), ServiceError> {
        info!("Installing ModSecurity for OpenLiteSpeed…");

        // Install libmodsecurity3 + OLS mod
        shell::exec(
            "apt-get",
            &["install", "-y", "libmodsecurity3", "libmodsecurity-dev"],
        )
        .await?;

        // Ensure directories exist
        fs::create_dir_all(MODSEC_RULES_DIR)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        // Create a minimal modsecurity.conf if it doesn't exist
        if !std::path::Path::new(MODSEC_MAIN_CONF).exists() {
            fs::create_dir_all("/etc/modsecurity")
                .await
                .map_err(|e| ServiceError::IoError(e.to_string()))?;
            let conf = minimal_modsec_conf();
            let tmp_modsec = format!("{}.panel_tmp", MODSEC_MAIN_CONF);
            fs::write(&tmp_modsec, conf)
                .await
                .map_err(|e| ServiceError::IoError(e.to_string()))?;
            fs::rename(&tmp_modsec, MODSEC_MAIN_CONF)
                .await
                .map_err(|e| ServiceError::IoError(e.to_string()))?;
        }

        info!("ModSecurity installed");
        Ok(())
    }

    /// Get current ModSecurity status.
    pub async fn get_status(&self) -> Result<ModSecStatus, ServiceError> {
        let installed = self.is_installed().await;
        let owasp_installed = std::path::Path::new(OWASP_DIR).exists();
        let comodo_installed = std::path::Path::new(COMODO_DIR).exists();

        let (engine_mode, enabled) = if installed {
            let mode = read_engine_mode().await;
            let en = mode != "Off";
            (mode, en)
        } else {
            ("Off".to_string(), false)
        };

        let rules_count = if std::path::Path::new(MODSEC_RULES_DIR).exists() {
            count_rules().await
        } else {
            0
        };

        Ok(ModSecStatus {
            installed,
            enabled,
            engine_mode,
            owasp_installed,
            comodo_installed,
            audit_log_path: MODSEC_AUDIT_LOG.to_string(),
            rules_count,
        })
    }

    /// Set the SecRuleEngine mode ("On", "Off", "DetectionOnly").
    pub async fn set_engine_mode(&self, mode: &str) -> Result<(), ServiceError> {
        if !matches!(mode, "On" | "Off" | "DetectionOnly") {
            return Err(ServiceError::CommandFailed(
                "mode must be 'On', 'Off', or 'DetectionOnly'".to_string(),
            ));
        }
        update_config_directive(MODSEC_MAIN_CONF, "SecRuleEngine", mode).await?;
        info!("ModSecurity engine mode set to {mode}");
        Ok(())
    }

    /// Install OWASP Core Rule Set (CRS).
    pub async fn install_owasp_crs(&self) -> Result<(), ServiceError> {
        info!("Installing OWASP CRS…");

        shell::exec("apt-get", &["install", "-y", "modsecurity-crs"])
            .await
            .ok();

        // If apt package not available, try downloading from GitHub release
        if !std::path::Path::new(OWASP_DIR).exists() {
            // Use curl to download CRS
            let owasp_url =
                "https://github.com/coreruleset/coreruleset/archive/refs/tags/v3.3.5.tar.gz";
            // SHA-256 of the canonical v3.3.5 release tarball (coreruleset/coreruleset).
            // Verified against https://github.com/coreruleset/coreruleset/releases/tag/v3.3.5
            const OWASP_CRS_SHA256: &str =
                "e4bcd8a3faeb534401c0e28427eb71d61e4c9a2a6731c1fe4d5a920a4cd7df11";
            fs::create_dir_all("/tmp/owasp-crs")
                .await
                .map_err(|e| ServiceError::IoError(e.to_string()))?;

            // Download (no shell injection risk; URL is a compile-time constant)
            shell::exec("curl", &["-fsSL", "-o", "/tmp/owasp-crs.tar.gz", owasp_url])
                .await
                .map_err(|_| {
                    ServiceError::CommandFailed("Failed to download OWASP CRS".to_string())
                })?;

            // Verify the SHA-256 checksum before extracting to prevent a
            // compromised CDN, MITM, or redirect from injecting malicious WAF rules.
            {
                use sha2::{Digest, Sha256};
                let tarball = fs::read("/tmp/owasp-crs.tar.gz")
                    .await
                    .map_err(|e| ServiceError::IoError(e.to_string()))?;
                let hash = hex::encode(Sha256::digest(&tarball));
                if hash != OWASP_CRS_SHA256 {
                    // Remove the suspect file before returning the error.
                    let _ = fs::remove_file("/tmp/owasp-crs.tar.gz").await;
                    return Err(ServiceError::CommandFailed(format!(
                        "OWASP CRS tarball checksum mismatch (got {hash}, expected {OWASP_CRS_SHA256})"
                    )));
                }
            }

            shell::exec(
                "tar",
                &[
                    "-xzf",
                    "/tmp/owasp-crs.tar.gz",
                    "-C",
                    "/tmp/owasp-crs",
                    "--strip-components=1",
                ],
            )
            .await?;

            // Move into place
            shell::exec("mv", &["/tmp/owasp-crs", OWASP_DIR])
                .await
                .map_err(|_| {
                    ServiceError::CommandFailed("Failed to install OWASP CRS".to_string())
                })?;
        }

        // Set up CRS setup.conf from example
        let crs_setup = format!("{}/crs-setup.conf", OWASP_DIR);
        let crs_setup_example = format!("{}/crs-setup.conf.example", OWASP_DIR);
        if !std::path::Path::new(&crs_setup).exists()
            && std::path::Path::new(&crs_setup_example).exists()
        {
            fs::copy(&crs_setup_example, &crs_setup)
                .await
                .map_err(|e| ServiceError::IoError(e.to_string()))?;
        }

        // Generate include conf
        write_owasp_include_conf().await?;

        info!("OWASP CRS installed");
        Ok(())
    }

    /// Install Comodo WAF rules.
    pub async fn install_comodo_waf(&self) -> Result<(), ServiceError> {
        info!("Installing Comodo WAF rules…");
        fs::create_dir_all(COMODO_DIR)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        // Comodo rules are available via their ModSecurity rules package
        // Write a basic placeholder rule set
        write_comodo_placeholder_rules().await?;

        info!("Comodo WAF rules installed");
        Ok(())
    }

    /// Enable/disable a specific rule set in the ModSecurity OLS config.
    pub async fn set_ruleset_enabled(
        &self,
        ruleset: &ModSecRuleSet,
        enabled: bool,
    ) -> Result<(), ServiceError> {
        let include_path = match ruleset {
            ModSecRuleSet::Owasp => format!("{}/crs-rules.conf", OWASP_DIR),
            ModSecRuleSet::Comodo => format!("{}/comodo-rules.conf", COMODO_DIR),
        };

        // Write/update the OLS modsec.conf include section
        update_ruleset_include(MODSEC_OLS_CONF, &include_path, enabled).await?;
        info!(
            "{} {} in ModSecurity",
            ruleset,
            if enabled { "enabled" } else { "disabled" }
        );
        Ok(())
    }

    /// Read the last N lines of the ModSecurity audit log.
    /// Uses Tokio file I/O instead of spawning `tail` to stay within the
    /// shell module's binary allowlist and avoid spawning extra processes.
    pub async fn get_audit_log(&self, lines: usize) -> Result<String, ServiceError> {
        if lines > 10000 {
            return Err(ServiceError::CommandFailed(
                "Too many lines requested".to_string(),
            ));
        }
        // Read the whole file; for a production audit log this may be large but
        // bounded by SecAuditLogRotation. Using seek-from-end would require a
        // synchronous file handle; reading then slicing is simpler and correct.
        let content = match fs::read_to_string(MODSEC_AUDIT_LOG).await {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
            Err(e) => return Err(ServiceError::IoError(e.to_string())),
        };
        let tail: String = content
            .lines()
            .rev()
            .take(lines)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .flat_map(|l| [l, "\n"])
            .collect();
        Ok(tail)
    }

    /// Parse recent audit log entries into structured form.
    pub async fn get_audit_entries(
        &self,
        limit: usize,
    ) -> Result<Vec<ModSecAuditEntry>, ServiceError> {
        let raw = self.get_audit_log(limit * 30).await.unwrap_or_default();
        Ok(parse_audit_log(&raw, limit))
    }

    /// Write the OpenLiteSpeed modsecurity configuration file.
    pub async fn write_ols_modsec_conf(&self, enabled: bool) -> Result<(), ServiceError> {
        let engine_mode = if enabled { "On" } else { "Off" };
        let conf = format!(
            r#"# ModSecurity configuration for OpenLiteSpeed
# Generated by hosting panel

SecRuleEngine {engine_mode}
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072

SecAuditEngine RelevantOnly
SecAuditLog {MODSEC_AUDIT_LOG}
SecAuditLogFormat Native
SecAuditLogParts ABCEFHIJZ

SecDebugLog /var/log/modsec_debug.log
SecDebugLogLevel 0

Include /etc/modsecurity/modsecurity.conf

"#
        );
        fs::create_dir_all("/usr/local/lsws/conf")
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;
        let tmp_ols = format!("{}.panel_tmp", MODSEC_OLS_CONF);
        fs::write(&tmp_ols, conf)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;
        fs::rename(&tmp_ols, MODSEC_OLS_CONF)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;
        Ok(())
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn minimal_modsec_conf() -> &'static str {
    r#"# ModSecurity Main Configuration
SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
SecResponseBodyAccess Off
SecResponseBodyMimeType text/plain text/html text/xml
SecResponseBodyLimit 524288
SecPcreMatchLimit 100000
SecPcreMatchLimitRecursion 100000
SecAuditEngine RelevantOnly
SecAuditLog /var/log/modsec_audit.log
SecAuditLogFormat Native
SecAuditLogParts ABCEFHIJZ
SecDebugLog /var/log/modsec_debug.log
SecDebugLogLevel 0
SecRequestBodyInMemoryLimit 131072
SecTmpDir /tmp/
SecDataDir /tmp/
SecRule REQUEST_HEADERS:Content-Type "(?:application(?:/soap\+|/)|text/)xml" \
    "id:200000,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
SecRule REQUEST_HEADERS:Content-Type "application/json" \
    "id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
"#
}

async fn read_engine_mode() -> String {
    let content = fs::read_to_string(MODSEC_MAIN_CONF)
        .await
        .unwrap_or_default();
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("SecRuleEngine") && !line.starts_with('#') {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                return parts[1].to_string();
            }
        }
    }
    "Off".to_string()
}

async fn update_config_directive(
    path: &str,
    directive: &str,
    value: &str,
) -> Result<(), ServiceError> {
    // SEC-35-03: hold an exclusive POSIX file lock for the whole read-modify-write
    // cycle so concurrent admin calls don't clobber each other's updates.
    let _lock = super::filelock::FileLock::exclusive(path)?;
    let content = fs::read_to_string(path).await.unwrap_or_default();

    let new_content: String = content
        .lines()
        .map(|line| {
            if line.trim().starts_with(directive) && !line.trim_start().starts_with('#') {
                format!("{} {}", directive, value)
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    let final_content = if !new_content.contains(directive) {
        format!("{}\n{} {}\n", new_content, directive, value)
    } else {
        new_content
    };

    let tmp_cfg = format!("{}.panel_tmp", path);
    fs::write(&tmp_cfg, final_content)
        .await
        .map_err(|e| ServiceError::IoError(e.to_string()))?;
    fs::rename(&tmp_cfg, path)
        .await
        .map_err(|e| ServiceError::IoError(e.to_string()))?;
    Ok(())
}

async fn update_ruleset_include(
    conf_path: &str,
    include_path: &str,
    enabled: bool,
) -> Result<(), ServiceError> {
    // SEC-35-03: same file-lock discipline as update_config_directive.
    let _lock = super::filelock::FileLock::exclusive(conf_path)?;
    let content = fs::read_to_string(conf_path).await.unwrap_or_default();

    let include_line = format!("Include {}", include_path);
    let commented_line = format!("#Include {}", include_path);

    let mut lines: Vec<String> = content
        .lines()
        .filter(|l| {
            !l.trim().starts_with(&format!("Include {}", include_path))
                && !l.trim().starts_with(&format!("#Include {}", include_path))
        })
        .map(|l| l.to_string())
        .collect();

    if enabled {
        lines.push(include_line);
    } else {
        lines.push(commented_line);
    }

    let new_content = lines.join("\n") + "\n";
    let tmp_ruleset = format!("{}.panel_tmp", conf_path);
    fs::write(&tmp_ruleset, new_content)
        .await
        .map_err(|e| ServiceError::IoError(e.to_string()))?;
    fs::rename(&tmp_ruleset, conf_path)
        .await
        .map_err(|e| ServiceError::IoError(e.to_string()))?;
    Ok(())
}

async fn count_rules() -> usize {
    let Ok(mut dir) = tokio::fs::read_dir(MODSEC_RULES_DIR).await else {
        return 0;
    };
    let mut count = 0;
    while let Ok(Some(entry)) = dir.next_entry().await {
        let name = entry.file_name();
        if name.to_string_lossy().ends_with(".conf") {
            count += 1;
        }
    }
    count
}

async fn write_owasp_include_conf() -> Result<(), ServiceError> {
    let conf_content = format!(
        r#"# OWASP CRS Include Configuration
# Auto-generated by hosting panel

Include {OWASP_DIR}/crs-setup.conf
Include {OWASP_DIR}/rules/*.conf
"#
    );
    fs::write(format!("{}/crs-rules.conf", OWASP_DIR), conf_content)
        .await
        .map_err(|e| ServiceError::IoError(e.to_string()))?;
    Ok(())
}

async fn write_comodo_placeholder_rules() -> Result<(), ServiceError> {
    // Comodo WAF rules require registration at https://waf.comodo.com/
    // These are placeholder rules mimicking Comodo WAF structure
    let conf_content = r#"# Comodo WAF Rules
# Register at https://waf.comodo.com/ for the full rule set
# Place downloaded rules in this directory

# Basic XSS protection
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_FILENAME|ARGS_NAMES|ARGS|XML:/* \
    "@rx <[[:space:]]*script" \
    "id:210001,phase:2,t:none,t:htmlEntityDecode,t:lowercase,deny,status:403,\
    log,msg:'Comodo WAF: XSS Attack Detected',severity:CRITICAL"

# Basic SQL injection protection
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS \
    "@rx (?i:(?:select|union|insert|update|delete|drop|truncate)\s)" \
    "id:210002,phase:2,t:none,t:urlDecode,t:htmlEntityDecode,deny,status:403,\
    log,msg:'Comodo WAF: SQL Injection Detected',severity:CRITICAL"

# Path traversal protection
SecRule REQUEST_URI|ARGS \
    "@rx \.\./" \
    "id:210003,phase:2,t:none,t:urlDecode,deny,status:403,\
    log,msg:'Comodo WAF: Path Traversal Detected',severity:HIGH"
"#;
    fs::write(format!("{}/comodo-rules.conf", COMODO_DIR), conf_content)
        .await
        .map_err(|e| ServiceError::IoError(e.to_string()))?;
    Ok(())
}

/// Parse the ModSecurity native audit log format.
fn parse_audit_log(raw: &str, limit: usize) -> Vec<ModSecAuditEntry> {
    let mut entries = Vec::new();
    let mut current_id = String::new();
    let mut current_ip = String::new();
    let mut current_uri = String::new();
    let mut current_method = String::new();
    let mut current_status = String::new();
    let mut current_timestamp = String::new();
    let mut current_rules: Vec<String> = Vec::new();
    let mut in_entry = false;

    for line in raw.lines() {
        // Section A: --<id>-A-- starts a new entry
        if line.contains("-A--") && line.starts_with("--") {
            if in_entry && !current_id.is_empty() {
                let severity = detect_severity(&current_rules);
                entries.push(ModSecAuditEntry {
                    timestamp: current_timestamp.clone(),
                    transaction_id: current_id.clone(),
                    client_ip: current_ip.clone(),
                    uri: current_uri.clone(),
                    method: current_method.clone(),
                    status: current_status.clone(),
                    matched_rules: current_rules.clone(),
                    severity,
                });
            }
            // Extract transaction id from "--<id>-A--"
            let parts: Vec<&str> = line.split('-').collect();
            if parts.len() >= 3 {
                current_id = parts[2].to_string();
            }
            current_ip = String::new();
            current_uri = String::new();
            current_method = String::new();
            current_status = String::new();
            current_timestamp = String::new();
            current_rules = Vec::new();
            in_entry = true;
        }
        // Timestamp + IP from section A header line
        else if in_entry && line.starts_with('[') {
            // [24/Dec/2023:12:00:00 +0000] <id> <ip> <sport> <dest_ip> <dport>
            if let Some(ts_end) = line.find(']') {
                current_timestamp = line[1..ts_end].to_string();
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                current_ip = parts[2].to_string();
            }
        }
        // Method + URI from request line (section B)
        else if in_entry
            && (line.starts_with("GET ")
                || line.starts_with("POST ")
                || line.starts_with("PUT ")
                || line.starts_with("DELETE ")
                || line.starts_with("PATCH ")
                || line.starts_with("HEAD "))
        {
            let parts: Vec<&str> = line.splitn(3, ' ').collect();
            if parts.len() >= 2 {
                current_method = parts[0].to_string();
                current_uri = parts[1].to_string();
            }
        }
        // Response status (section F or H)
        else if in_entry && line.starts_with("HTTP/") {
            let parts: Vec<&str> = line.splitn(3, ' ').collect();
            if parts.len() >= 2 {
                current_status = parts[1].to_string();
            }
        }
        // Matched rule (section H or K)
        else if in_entry && line.contains("Message:") {
            current_rules.push(line.trim().to_string());
        }
    }

    // Push last entry
    if in_entry && !current_id.is_empty() {
        let severity = detect_severity(&current_rules);
        entries.push(ModSecAuditEntry {
            timestamp: current_timestamp,
            transaction_id: current_id,
            client_ip: current_ip,
            uri: current_uri,
            method: current_method,
            status: current_status,
            matched_rules: current_rules,
            severity,
        });
    }

    entries.into_iter().rev().take(limit).collect()
}

fn detect_severity(rules: &[String]) -> String {
    for rule in rules {
        let lower = rule.to_lowercase();
        if lower.contains("critical") {
            return "CRITICAL".to_string();
        }
        if lower.contains("error") {
            return "ERROR".to_string();
        }
        if lower.contains("warning") {
            return "WARNING".to_string();
        }
    }
    if rules.is_empty() {
        "INFO".to_string()
    } else {
        "NOTICE".to_string()
    }
}
