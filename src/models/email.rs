use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Email domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(sqlx::FromRow))]
pub struct EmailDomain {
    pub id: i64,
    pub owner_id: i64,
    pub domain: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    /// 0 = unlimited
    #[serde(default)]
    pub send_limit_per_hour: i32,
    /// 0 = unlimited
    #[serde(default)]
    pub send_limit_per_day: i32,
    /// Catch-all destination address; None = disabled.
    #[serde(default)]
    pub catch_all_address: Option<String>,
    /// Whether `user+tag@domain` plus-addressing is active for this domain.
    #[serde(default)]
    pub plus_addressing_enabled: bool,
}

/// Mailbox account.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(sqlx::FromRow))]
pub struct Mailbox {
    pub id: i64,
    pub domain_id: i64,
    pub local_part: String,
    #[serde(skip)]
    pub password_hash: String,
    pub quota_mb: i32,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

/// Email forwarder.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(sqlx::FromRow))]
pub struct EmailForwarder {
    pub id: i64,
    pub domain_id: i64,
    pub local_part: String,
    pub forward_to: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateMailboxRequest {
    pub local_part: String,
    pub password: String,
    #[serde(default = "default_quota")]
    pub quota_mb: i32,
}

fn default_quota() -> i32 {
    256
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateForwarderRequest {
    pub local_part: String,
    pub forward_to: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChangeMailboxPassword {
    pub new_password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SetSendLimitsRequest {
    pub domain_id: i64,
    /// Maximum emails per hour; 0 = unlimited
    pub limit_per_hour: i32,
    /// Maximum emails per day; 0 = unlimited
    pub limit_per_day: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EmailDomainWithAccounts {
    pub domain: EmailDomain,
    pub mailboxes: Vec<Mailbox>,
    pub forwarders: Vec<EmailForwarder>,
}

/// Regex-based email forwarder (Postfix regexp virtual_alias map).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(sqlx::FromRow))]
pub struct RegexForwarder {
    pub id: i64,
    pub domain_id: i64,
    /// POSIX extended regex, e.g. `^sales\+.*@`
    pub pattern: String,
    pub forward_to: String,
    pub description: Option<String>,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateRegexForwarderRequest {
    pub pattern: String,
    pub forward_to: String,
    pub description: Option<String>,
}

/// DKIM signing key record stored in the panel DB.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(sqlx::FromRow))]
pub struct DkimKey {
    pub id: i64,
    pub domain_id: i64,
    pub domain: String,
    pub selector: String,
    /// Full DNS TXT record value suitable for publishing (e.g. `v=DKIM1; k=rsa; p=…`).
    pub public_key_dns: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Anti-spam & mail security models
// ═══════════════════════════════════════════════════════════════════════════════

/// Global spam-filter settings (single-row config).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(sqlx::FromRow))]
pub struct SpamFilterSettings {
    pub id: i64,
    /// Active engine: "none", "spamassassin", or "rspamd".
    pub engine: String,
    /// Score threshold above which mail is tagged/rejected.
    pub spam_threshold: f64,
    /// Add X-Spam-Status header when score >= threshold.
    pub add_header_enabled: bool,
    /// Move spam to quarantine mailbox instead of delivering.
    pub quarantine_enabled: bool,
    /// Quarantine destination address.
    pub quarantine_mailbox: Option<String>,
    /// Score at which mail is outright rejected (0 = disabled).
    pub reject_score: f64,
    /// Whether ClamAV virus scanning via amavisd/clamsmtpd is active.
    pub clamav_enabled: bool,
    /// Whether MailScanner is active.
    pub mailscanner_enabled: bool,
    pub updated_at: DateTime<Utc>,
}

/// A single entry from the Postfix mail queue (`mailq` output).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailQueueEntry {
    pub queue_id: String,
    pub size: u64,
    /// ISO-8601 timestamp of arrival.
    pub arrival_time: String,
    pub sender: String,
    pub recipient: String,
    /// Delivery status reason (if deferred/bounced).
    pub reason: String,
    /// "deferred", "active", "hold", "corrupt", or "incoming".
    pub queue_type: String,
}

/// Summary statistics for a single day / domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(sqlx::FromRow))]
pub struct EmailStats {
    pub id: i64,
    pub stat_date: String,
    pub domain: Option<String>,
    pub sent_count: i64,
    pub received_count: i64,
    pub rejected_count: i64,
    pub spam_count: i64,
    pub bounced_count: i64,
}

/// A single parsed mail-log entry for the log viewer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailLogEntry {
    pub timestamp: String,
    pub hostname: String,
    pub process: String,
    pub queue_id: String,
    pub message: String,
}

/// Result of the email debugger probe for a given address / domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailDebugResult {
    pub target: String,
    pub mx_records: Vec<String>,
    pub spf_record: Option<String>,
    pub dkim_record: Option<String>,
    pub dmarc_record: Option<String>,
    pub mx_reachable: bool,
    pub smtp_banner: Option<String>,
    pub test_sent: bool,
    pub notes: Vec<String>,
}

/// Request to set per-mailbox rate limits.
#[derive(Debug, Serialize, Deserialize)]
pub struct SetMailboxRateLimitRequest {
    pub mailbox_id: i64,
    pub limit_per_hour: i32,
    pub limit_per_day: i32,
}

/// Per-mailbox filesystem statistics derived from the Maildir on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxStats {
    pub mailbox_id: i64,
    /// Full address: `local_part@domain`
    pub address: String,
    /// Total messages across all folders (cur + new sub-dirs).
    pub messages_total: u64,
    /// Unread messages (files in `new/`).
    pub messages_new: u64,
    /// Disk usage in kilobytes.
    pub disk_usage_kb: u64,
    /// Configured quota in MB.
    pub quota_mb: i32,
    /// Quota utilisation percentage, 0–100.
    pub quota_used_pct: f64,
}

/// One-time signed token returned after creating a mailbox backup archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxBackupToken {
    /// URL the client should GET to download the `.tar.gz` archive.
    pub download_url: String,
    /// Suggested download filename (e.g. `alice@example.com_2026-03-10.tar.gz`).
    pub filename: String,
    /// Archive size in bytes.
    pub size_bytes: u64,
}
