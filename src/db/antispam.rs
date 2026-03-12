/// Database operations for anti-spam settings, mail stats, and mailbox rate limits.
use crate::models::email::{EmailStats, SpamFilterSettings};
use sqlx::SqlitePool;

// ─── Spam filter settings ────────────────────────────────────────────────────

/// Get the singleton spam-filter settings row.
pub async fn get_spam_filter_settings(
    pool: &SqlitePool,
) -> Result<SpamFilterSettings, sqlx::Error> {
    sqlx::query_as::<_, SpamFilterSettings>("SELECT * FROM spam_filter_settings WHERE id = 1")
        .fetch_one(pool)
        .await
}

/// Persist spam-filter settings (upsert on the single config row).
pub async fn save_spam_filter_settings(
    pool: &SqlitePool,
    engine: &str,
    spam_threshold: f64,
    add_header_enabled: bool,
    quarantine_enabled: bool,
    quarantine_mailbox: Option<&str>,
    reject_score: f64,
    clamav_enabled: bool,
    mailscanner_enabled: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO spam_filter_settings
             (id, engine, spam_threshold, add_header_enabled, quarantine_enabled,
              quarantine_mailbox, reject_score, clamav_enabled, mailscanner_enabled, updated_at)
         VALUES (1,?,?,?,?,?,?,?,?, datetime('now'))
         ON CONFLICT(id) DO UPDATE SET
             engine = excluded.engine,
             spam_threshold = excluded.spam_threshold,
             add_header_enabled = excluded.add_header_enabled,
             quarantine_enabled = excluded.quarantine_enabled,
             quarantine_mailbox = excluded.quarantine_mailbox,
             reject_score = excluded.reject_score,
             clamav_enabled = excluded.clamav_enabled,
             mailscanner_enabled = excluded.mailscanner_enabled,
             updated_at = excluded.updated_at",
    )
    .bind(engine)
    .bind(spam_threshold)
    .bind(add_header_enabled)
    .bind(quarantine_enabled)
    .bind(quarantine_mailbox)
    .bind(reject_score)
    .bind(clamav_enabled)
    .bind(mailscanner_enabled)
    .execute(pool)
    .await?;
    Ok(())
}

// ─── Per-mailbox rate limits ─────────────────────────────────────────────────

/// Set per-mailbox hourly/daily send limits.
pub async fn set_mailbox_rate_limits(
    pool: &SqlitePool,
    mailbox_id: i64,
    limit_per_hour: i32,
    limit_per_day: i32,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE mailboxes SET send_limit_per_hour = ?, send_limit_per_day = ? WHERE id = ?",
    )
    .bind(limit_per_hour)
    .bind(limit_per_day)
    .bind(mailbox_id)
    .execute(pool)
    .await?;
    Ok(())
}

// ─── Email statistics ────────────────────────────────────────────────────────

/// Upsert a daily stats row.
pub async fn upsert_email_stats(
    pool: &SqlitePool,
    stat_date: &str,
    domain: Option<&str>,
    sent: i64,
    received: i64,
    rejected: i64,
    spam: i64,
    bounced: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO email_stats (stat_date, domain, sent_count, received_count, rejected_count, spam_count, bounced_count)
         VALUES (?,?,?,?,?,?,?)
         ON CONFLICT(stat_date, domain) DO UPDATE SET
             sent_count     = sent_count     + excluded.sent_count,
             received_count = received_count + excluded.received_count,
             rejected_count = rejected_count + excluded.rejected_count,
             spam_count     = spam_count     + excluded.spam_count,
             bounced_count  = bounced_count  + excluded.bounced_count",
    )
    .bind(stat_date)
    .bind(domain)
    .bind(sent)
    .bind(received)
    .bind(rejected)
    .bind(spam)
    .bind(bounced)
    .execute(pool)
    .await?;
    Ok(())
}

/// List email stats for the last N days.
pub async fn list_email_stats(
    pool: &SqlitePool,
    days: i64,
) -> Result<Vec<EmailStats>, sqlx::Error> {
    sqlx::query_as::<_, EmailStats>(
        "SELECT * FROM email_stats
         WHERE stat_date >= date('now', ?1)
         ORDER BY stat_date DESC, domain",
    )
    .bind(format!("-{days} days"))
    .fetch_all(pool)
    .await
}
