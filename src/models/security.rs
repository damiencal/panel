/// Security data models (WAF, ClamAV, SSH) shared between frontend and backend.
use serde::{Deserialize, Serialize};

// ─── ModSecurity ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ModSecRuleSet {
    Owasp,
    Comodo,
}

impl std::fmt::Display for ModSecRuleSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModSecRuleSet::Owasp => write!(f, "OWASP CRS"),
            ModSecRuleSet::Comodo => write!(f, "Comodo WAF"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModSecStatus {
    pub installed: bool,
    pub enabled: bool,
    pub engine_mode: String, // "On", "Off", "DetectionOnly"
    pub owasp_installed: bool,
    pub comodo_installed: bool,
    pub audit_log_path: String,
    pub rules_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModSecAuditEntry {
    pub timestamp: String,
    pub transaction_id: String,
    pub client_ip: String,
    pub uri: String,
    pub method: String,
    pub status: String,
    pub matched_rules: Vec<String>,
    pub severity: String,
}

// ─── ClamAV ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClamScanReport {
    pub scanned_files: usize,
    pub infected_files: usize,
    pub threats: Vec<ClamThreat>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClamThreat {
    pub path: String,
    pub virus_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClamDbInfo {
    pub version: String,
    pub signatures: u64,
    pub database_date: String,
}

// ─── SSH Hardening ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshConfig {
    pub port: u16,
    pub permit_root_login: String,
    pub password_authentication: bool,
    pub pubkey_authentication: bool,
    pub max_auth_tries: u8,
    pub login_grace_time: u16,
    pub allow_agent_forwarding: bool,
    pub x11_forwarding: bool,
    pub use_pam: bool,
    pub ignore_rhosts: bool,
    pub permit_empty_passwords: bool,
    pub challenge_response_authentication: bool,
    pub use_dns: bool,
    pub banner_enabled: bool,
    pub allowed_users: Vec<String>,
    pub client_alive_interval: u16,
    pub client_alive_count_max: u8,
    pub max_sessions: u8,
    pub max_startups: String,
    pub ciphers: String,
    pub macs: String,
    pub kex_algorithms: String,
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            port: 22,
            permit_root_login: "prohibit-password".to_string(),
            password_authentication: false,
            pubkey_authentication: true,
            max_auth_tries: 3,
            login_grace_time: 60,
            allow_agent_forwarding: false,
            x11_forwarding: false,
            use_pam: true,
            ignore_rhosts: true,
            permit_empty_passwords: false,
            challenge_response_authentication: false,
            use_dns: false,
            banner_enabled: true,
            allowed_users: Vec::new(),
            client_alive_interval: 300,
            client_alive_count_max: 2,
            max_sessions: 4,
            max_startups: "10:30:100".to_string(),
            ciphers: "aes256-gcm@openssh.com,aes128-gcm@openssh.com,chacha20-poly1305@openssh.com"
                .to_string(),
            macs: "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com".to_string(),
            kex_algorithms: "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521"
                .to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshHardeningResult {
    pub success: bool,
    pub message: String,
    pub warnings: Vec<String>,
}
