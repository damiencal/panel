/// Anti-spam, mail queue, email statistics, and email debugger server functions.
use crate::models::email::{
    EmailDebugResult, EmailLogEntry, EmailStats, MailQueueEntry, SpamFilterSettings,
};
#[cfg(feature = "server")]
use crate::services::ManagedService;
use dioxus::prelude::*;

// ═══════════════════════════════════════════════════════════════════════════════
// Spam-filter settings
// ═══════════════════════════════════════════════════════════════════════════════

/// Get the current spam-filter configuration (admin only).
#[server]
pub async fn server_get_spam_filter_settings() -> Result<SpamFilterSettings, ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;
    crate::db::antispam::get_spam_filter_settings(pool)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Save spam-filter settings and apply them to the system (admin only).
/// This will install / configure the selected engine and wire it into Postfix.
#[server]
pub async fn server_save_spam_filter_settings(
    engine: String,
    spam_threshold: f64,
    add_header_enabled: bool,
    quarantine_enabled: bool,
    quarantine_mailbox: Option<String>,
    reject_score: f64,
    clamav_enabled: bool,
    mailscanner_enabled: bool,
) -> Result<(), ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;

    if !matches!(engine.as_str(), "none" | "spamassassin" | "rspamd") {
        return Err(ServerFnError::new("Invalid engine selection"));
    }
    if spam_threshold < 0.0 || spam_threshold > 100.0 {
        return Err(ServerFnError::new(
            "Spam threshold must be between 0 and 100",
        ));
    }

    // Persist to DB
    crate::db::antispam::save_spam_filter_settings(
        pool,
        &engine,
        spam_threshold,
        add_header_enabled,
        quarantine_enabled,
        quarantine_mailbox.as_deref(),
        reject_score,
        clamav_enabled,
        mailscanner_enabled,
    )
    .await
    .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Apply configuration
    match engine.as_str() {
        "spamassassin" => {
            let svc = crate::services::spamassassin::SpamAssassinService;
            let installed = svc.is_installed().await.unwrap_or(false);
            if !installed {
                svc.install()
                    .await
                    .map_err(|e| ServerFnError::new(e.to_string()))?;
            }
            svc.configure(spam_threshold, add_header_enabled, reject_score)
                .await
                .map_err(|e| ServerFnError::new(e.to_string()))?;
            svc.integrate_with_postfix(true)
                .await
                .map_err(|e| ServerFnError::new(e.to_string()))?;
            // Disable rspamd milter if switching back
            let rspamd = crate::services::rspamd::RspamdService;
            rspamd.integrate_with_postfix(false).await.ok();
        }
        "rspamd" => {
            let rspamd = crate::services::rspamd::RspamdService;
            let installed = rspamd.is_installed().await.unwrap_or(false);
            if !installed {
                rspamd
                    .install()
                    .await
                    .map_err(|e| ServerFnError::new(e.to_string()))?;
            }
            rspamd
                .configure(
                    spam_threshold,
                    add_header_enabled,
                    reject_score,
                    clamav_enabled,
                )
                .await
                .map_err(|e| ServerFnError::new(e.to_string()))?;
            rspamd
                .integrate_with_postfix(true)
                .await
                .map_err(|e| ServerFnError::new(e.to_string()))?;
            // Disable SA content_filter if switching
            let sa = crate::services::spamassassin::SpamAssassinService;
            sa.integrate_with_postfix(false).await.ok();

            // ClamAV
            if clamav_enabled {
                let clamav = crate::services::rspamd::ClamAvService;
                let clam_installed = clamav.is_installed().await.unwrap_or(false);
                if !clam_installed {
                    clamav
                        .install()
                        .await
                        .map_err(|e| ServerFnError::new(e.to_string()))?;
                }
                clamav.start().await.ok();
            }
        }
        "none" => {
            // Disable both integrations
            let sa = crate::services::spamassassin::SpamAssassinService;
            sa.integrate_with_postfix(false).await.ok();
            let rspamd = crate::services::rspamd::RspamdService;
            rspamd.integrate_with_postfix(false).await.ok();
        }
        _ => {}
    }

    // MailScanner
    if mailscanner_enabled {
        let ms = crate::services::mailscanner::MailScannerService;
        let ms_installed = ms.is_installed().await.unwrap_or(false);
        if !ms_installed {
            ms.install()
                .await
                .map_err(|e| ServerFnError::new(e.to_string()))?;
        }
        ms.configure(true).await.ok();
        ms.start().await.ok();
    }

    audit_log(
        claims.sub,
        "save_spam_filter_settings",
        Some("spam_filter"),
        Some(1),
        Some(&engine),
        "Success",
        None,
    )
    .await;

    Ok(())
}

/// Get the installed / running status of each anti-spam component (admin only).
#[server]
pub async fn server_get_antispam_service_status() -> Result<Vec<(String, bool, bool)>, ServerFnError>
{
    use super::helpers::*;
    use crate::services::ManagedService;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;

    let mut results = Vec::new();

    let sa = crate::services::spamassassin::SpamAssassinService;
    let sa_installed = sa.is_installed().await.unwrap_or(false);
    let sa_running = matches!(
        sa.status()
            .await
            .unwrap_or(crate::models::service::ServiceStatus::Stopped),
        crate::models::service::ServiceStatus::Running
    );
    results.push(("SpamAssassin".to_string(), sa_installed, sa_running));

    let rspamd = crate::services::rspamd::RspamdService;
    let rs_installed = rspamd.is_installed().await.unwrap_or(false);
    let rs_running = matches!(
        rspamd
            .status()
            .await
            .unwrap_or(crate::models::service::ServiceStatus::Stopped),
        crate::models::service::ServiceStatus::Running
    );
    results.push(("Rspamd".to_string(), rs_installed, rs_running));

    let clamav = crate::services::rspamd::ClamAvService;
    let clam_installed = clamav.is_installed().await.unwrap_or(false);
    let clam_running = matches!(
        clamav
            .status()
            .await
            .unwrap_or(crate::models::service::ServiceStatus::Stopped),
        crate::models::service::ServiceStatus::Running
    );
    results.push(("ClamAV".to_string(), clam_installed, clam_running));

    let ms = crate::services::mailscanner::MailScannerService;
    let ms_installed = ms.is_installed().await.unwrap_or(false);
    let ms_running = matches!(
        ms.status()
            .await
            .unwrap_or(crate::models::service::ServiceStatus::Stopped),
        crate::models::service::ServiceStatus::Running
    );
    results.push(("MailScanner".to_string(), ms_installed, ms_running));

    Ok(results)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Per-mailbox rate limits
// ═══════════════════════════════════════════════════════════════════════════════

/// Set per-mailbox send-rate limits (domain owner or admin).
#[server]
pub async fn server_set_mailbox_rate_limits(
    domain_id: i64,
    mailbox_id: i64,
    limit_per_hour: i32,
    limit_per_day: i32,
) -> Result<(), ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let domain = crate::db::email::get_domain(pool, domain_id)
        .await
        .map_err(|_| ServerFnError::new("Domain not found"))?;
    crate::auth::guards::check_ownership(&claims, domain.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    if limit_per_hour < 0 || limit_per_day < 0 {
        return Err(ServerFnError::new(
            "Limits must be non-negative (0 = unlimited)",
        ));
    }

    crate::db::antispam::set_mailbox_rate_limits(pool, mailbox_id, limit_per_hour, limit_per_day)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "set_mailbox_rate_limits",
        Some("mailbox"),
        Some(mailbox_id),
        Some(&format!("hourly={limit_per_hour} daily={limit_per_day}")),
        "Success",
        None,
    )
    .await;
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Mail queue manager
// ═══════════════════════════════════════════════════════════════════════════════

/// List all messages in the Postfix mail queue (admin only).
#[server]
pub async fn server_list_mail_queue() -> Result<Vec<MailQueueEntry>, ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;

    crate::services::mail_queue::list_queue()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Flush the deferred mail queue — attempt immediate redelivery (admin only).
#[server]
pub async fn server_flush_mail_queue() -> Result<(), ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;

    crate::services::mail_queue::flush_queue()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "flush_mail_queue",
        None,
        None,
        None,
        "Success",
        None,
    )
    .await;
    Ok(())
}

/// Delete a specific message from the mail queue (admin only).
#[server]
pub async fn server_delete_queued_message(queue_id: String) -> Result<(), ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;

    crate::services::mail_queue::delete_message(&queue_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "delete_queued_message",
        Some("mail_queue"),
        None,
        Some(&queue_id),
        "Success",
        None,
    )
    .await;
    Ok(())
}

/// Delete all deferred messages from the mail queue (admin only).
#[server]
pub async fn server_delete_all_deferred() -> Result<(), ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;

    crate::services::mail_queue::delete_all_deferred()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "delete_all_deferred",
        None,
        None,
        None,
        "Success",
        None,
    )
    .await;
    Ok(())
}

/// Hold a queued message (admin only).
#[server]
pub async fn server_hold_queued_message(queue_id: String) -> Result<(), ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;

    crate::services::mail_queue::hold_message(&queue_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(())
}

/// Release a held queued message (admin only).
#[server]
pub async fn server_release_queued_message(queue_id: String) -> Result<(), ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;

    crate::services::mail_queue::release_message(&queue_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Email statistics and log viewer
// ═══════════════════════════════════════════════════════════════════════════════

/// Get aggregated email statistics for the last N days (admin only).
#[server]
pub async fn server_get_email_stats(days: i64) -> Result<Vec<EmailStats>, ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;

    let days = days.clamp(1, 90);
    crate::db::antispam::list_email_stats(pool, days)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Get recent lines from the mail log (admin only).
/// Returns up to `limit` lines, optionally filtered by `search`.
#[server]
pub async fn server_get_mail_logs(
    limit: usize,
    search: Option<String>,
) -> Result<Vec<EmailLogEntry>, ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;

    let limit = limit.clamp(1, 500);
    read_mail_logs(limit, search.as_deref())
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Parse daily stats from the mail log and write them to the DB (admin only).
/// This is a manual trigger for log ingestion; in production this would be scheduled.
#[server]
pub async fn server_ingest_mail_stats() -> Result<String, ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;

    let (sent, received, rejected, spam, bounced) = parse_log_stats_today()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    crate::db::antispam::upsert_email_stats(
        pool, &today, None, sent, received, rejected, spam, bounced,
    )
    .await
    .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(format!(
        "Ingested: sent={sent} received={received} rejected={rejected} spam={spam} bounced={bounced}"
    ))
}

// ═══════════════════════════════════════════════════════════════════════════════
// Email debugger
// ═══════════════════════════════════════════════════════════════════════════════

/// Debug the email delivery path for a given domain (admin only).
/// Checks MX, SPF, DKIM, DMARC records and optionally probes SMTP.
#[server]
pub async fn server_debug_email(domain: String) -> Result<EmailDebugResult, ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;

    crate::utils::validators::validate_domain(&domain).map_err(ServerFnError::new)?;

    debug_domain(&domain)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

// ─── Server-only helpers ─────────────────────────────────────────────────────

#[cfg(feature = "server")]
async fn read_mail_logs(limit: usize, search: Option<&str>) -> Result<Vec<EmailLogEntry>, String> {
    use tokio::fs::File;
    use tokio::io::{AsyncBufReadExt, BufReader};

    // Try common mail log paths
    let log_paths = ["/var/log/mail.log", "/var/log/maillog", "/var/log/syslog"];

    let mut entries: Vec<EmailLogEntry> = Vec::new();

    for path in &log_paths {
        if let Ok(file) = File::open(path).await {
            let reader = BufReader::new(file);
            let mut lines = reader.lines();
            let mut all_lines: Vec<String> = Vec::new();

            while let Ok(Some(line)) = lines.next_line().await {
                if line.contains("postfix") || line.contains("spamd") || line.contains("rspamd") {
                    if let Some(ref s) = search {
                        if line.to_lowercase().contains(&s.to_lowercase()) {
                            all_lines.push(line);
                        }
                    } else {
                        all_lines.push(line);
                    }
                }
            }

            // Take the last `limit` entries
            let start = all_lines.len().saturating_sub(limit);
            for line in all_lines[start..].iter().rev() {
                entries.push(parse_log_line(line));
            }

            if !entries.is_empty() {
                break;
            }
        }
    }

    Ok(entries)
}

#[cfg(feature = "server")]
fn parse_log_line(line: &str) -> EmailLogEntry {
    // Typical format: "Mar  9 14:23:01 hostname postfix/smtp[1234]: ABCDE: ..."
    let parts: Vec<&str> = line.splitn(5, ' ').filter(|s| !s.is_empty()).collect();
    if parts.len() >= 5 {
        let timestamp = format!("{} {} {}", parts[0], parts[1], parts[2]);
        let hostname = parts[3].to_string();
        let rest = parts[4];
        let (process, msg) = rest.split_once(": ").unwrap_or(("", rest));
        let (queue_id, message) = msg.split_once(": ").unwrap_or(("", msg));
        EmailLogEntry {
            timestamp,
            hostname,
            process: process.to_string(),
            queue_id: queue_id.trim().to_string(),
            message: message.trim().to_string(),
        }
    } else {
        EmailLogEntry {
            timestamp: String::new(),
            hostname: String::new(),
            process: String::new(),
            queue_id: String::new(),
            message: line.to_string(),
        }
    }
}

#[cfg(feature = "server")]
async fn parse_log_stats_today() -> Result<(i64, i64, i64, i64, i64), String> {
    use tokio::fs::File;
    use tokio::io::{AsyncBufReadExt, BufReader};

    let today_prefix = chrono::Utc::now().format("%b %e").to_string();
    let mut sent = 0i64;
    let mut received = 0i64;
    let mut rejected = 0i64;
    let mut spam = 0i64;
    let mut bounced = 0i64;

    for path in &["/var/log/mail.log", "/var/log/maillog"] {
        if let Ok(file) = File::open(path).await {
            let reader = BufReader::new(file);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if !line.starts_with(&today_prefix) {
                    continue;
                }
                let l = line.to_lowercase();
                if l.contains("status=sent") {
                    sent += 1;
                } else if l.contains("message-id=") && l.contains("postfix/smtpd") {
                    received += 1;
                } else if l.contains("reject:") || l.contains("rejected") {
                    rejected += 1;
                } else if l.contains("x-spam-flag: yes") || l.contains("spam detected") {
                    spam += 1;
                } else if l.contains("status=bounced") {
                    bounced += 1;
                }
            }
        }
    }

    Ok((sent, received, rejected, spam, bounced))
}

#[cfg(feature = "server")]
async fn debug_domain(domain: &str) -> Result<EmailDebugResult, String> {
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::net::TcpStream;
    use tokio::time::timeout;

    let mut notes = Vec::new();
    let mut mx_records = Vec::new();
    let mut spf_record = None;
    let mut dkim_record = None;
    let mut dmarc_record = None;
    let mut mx_reachable = false;
    let mut smtp_banner = None;

    // MX lookup
    match lookup_dns_txt(&format!("{domain}"), "MX").await {
        Ok(records) => {
            mx_records = records;
            if mx_records.is_empty() {
                notes.push(
                    "No MX records found — mail cannot be delivered to this domain".to_string(),
                );
            }
        }
        Err(e) => notes.push(format!("MX lookup failed: {e}")),
    }

    // SPF lookup
    match lookup_dns_txt(&format!("{domain}"), "TXT").await {
        Ok(records) => {
            for r in &records {
                if r.starts_with("v=spf1") {
                    spf_record = Some(r.clone());
                    break;
                }
            }
            if spf_record.is_none() {
                notes.push(
                    "No SPF record found — outbound emails may be rejected as spam".to_string(),
                );
            }
        }
        Err(e) => notes.push(format!("SPF/TXT lookup failed: {e}")),
    }

    // DKIM lookup (default._domainkey)
    match lookup_dns_txt(&format!("default._domainkey.{domain}"), "TXT").await {
        Ok(records) if !records.is_empty() => {
            dkim_record = Some(records[0].clone());
        }
        _ => {
            notes.push(
                "No DKIM record at default._domainkey — outbound emails may be rejected"
                    .to_string(),
            );
        }
    }

    // DMARC lookup
    match lookup_dns_txt(&format!("_dmarc.{domain}"), "TXT").await {
        Ok(records) => {
            for r in &records {
                if r.starts_with("v=DMARC1") {
                    dmarc_record = Some(r.clone());
                    break;
                }
            }
            if dmarc_record.is_none() {
                notes.push(
                    "No DMARC record — consider adding _dmarc TXT record for policy enforcement"
                        .to_string(),
                );
            }
        }
        _ => {
            notes.push("DMARC lookup failed".to_string());
        }
    }

    // Probe first MX host on port 25
    if let Some(mx) = mx_records.first() {
        let host = mx
            .split_whitespace()
            .last()
            .unwrap_or(mx)
            .trim_end_matches('.');
        if let Ok(Ok(mut stream)) = timeout(
            Duration::from_secs(5),
            TcpStream::connect(format!("{host}:25")),
        )
        .await
        {
            mx_reachable = true;
            let mut reader = BufReader::new(&mut stream);
            let mut banner_line = String::new();
            if reader.read_line(&mut banner_line).await.is_ok() {
                smtp_banner = Some(banner_line.trim().to_string());
            }
        } else {
            notes.push(format!(
                "MX host {host}:25 is not reachable from this server"
            ));
        }
    }

    Ok(EmailDebugResult {
        target: domain.to_string(),
        mx_records,
        spf_record,
        dkim_record,
        dmarc_record,
        mx_reachable,
        smtp_banner,
        test_sent: false,
        notes,
    })
}

/// Query DNS via Cloudflare DNS-over-HTTPS (no system DNS tools required).
#[cfg(feature = "server")]
async fn lookup_dns_txt(name: &str, record_type: &str) -> Result<Vec<String>, String> {
    use reqwest::Client;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct DoHAnswer {
        data: String,
    }

    #[derive(Deserialize)]
    #[allow(non_snake_case)]
    struct DoHResponse {
        Status: i32,
        Answer: Option<Vec<DoHAnswer>>,
    }

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .map_err(|e| format!("HTTP client error: {e}"))?;

    let url = format!("https://cloudflare-dns.com/dns-query?name={name}&type={record_type}");

    let resp = client
        .get(&url)
        .header("Accept", "application/dns-json")
        .send()
        .await
        .map_err(|e| format!("DNS query failed: {e}"))?;

    let body: DoHResponse = resp
        .json()
        .await
        .map_err(|e| format!("DNS response parse error: {e}"))?;

    if body.Status != 0 {
        return Ok(vec![]);
    }

    let records = body
        .Answer
        .unwrap_or_default()
        .into_iter()
        .map(|a| {
            // Strip surrounding quotes that some DoH implementations include for TXT
            let d = a.data;
            if d.starts_with('"') && d.ends_with('"') && d.len() > 1 {
                d[1..d.len() - 1].to_string()
            } else {
                d
            }
        })
        .collect();

    Ok(records)
}
