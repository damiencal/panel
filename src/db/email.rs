/// Email domain, mailbox, and forwarder operations.
use crate::models::email::{DkimKey, EmailDomain, Mailbox, RegexForwarder};
use chrono::Utc;
use sqlx::SqlitePool;

/// Get an email domain by ID.
pub async fn get_domain(pool: &SqlitePool, domain_id: i64) -> Result<EmailDomain, sqlx::Error> {
    sqlx::query_as::<_, EmailDomain>("SELECT * FROM email_domains WHERE id = ?")
        .bind(domain_id)
        .fetch_one(pool)
        .await
}

/// List email domains for an owner.
pub async fn list_domains(
    pool: &SqlitePool,
    owner_id: i64,
) -> Result<Vec<EmailDomain>, sqlx::Error> {
    sqlx::query_as::<_, EmailDomain>(
        "SELECT * FROM email_domains WHERE owner_id = ? ORDER BY domain",
    )
    .bind(owner_id)
    .fetch_all(pool)
    .await
}

/// Create an email domain.
pub async fn create_domain(
    pool: &SqlitePool,
    owner_id: i64,
    domain: String,
) -> Result<i64, sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO email_domains (owner_id, domain, status, created_at)
         VALUES (?, ?, ?, ?)",
    )
    .bind(owner_id)
    .bind(domain)
    .bind("Active")
    .bind(Utc::now())
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

/// List all email domains regardless of owner (admin use).
pub async fn list_all_domains(pool: &SqlitePool) -> Result<Vec<EmailDomain>, sqlx::Error> {
    sqlx::query_as::<_, EmailDomain>("SELECT * FROM email_domains ORDER BY domain")
        .fetch_all(pool)
        .await
}

/// Set per-domain send limits. Pass 0 for unlimited.
pub async fn set_send_limits(
    pool: &SqlitePool,
    domain_id: i64,
    limit_per_hour: i32,
    limit_per_day: i32,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE email_domains SET send_limit_per_hour = ?, send_limit_per_day = ? WHERE id = ?",
    )
    .bind(limit_per_hour)
    .bind(limit_per_day)
    .bind(domain_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn create_mailbox(
    pool: &SqlitePool,
    domain_id: i64,
    local_part: String,
    password_hash: String,
) -> Result<i64, sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO mailboxes (domain_id, local_part, password_hash, status, created_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(domain_id)
    .bind(local_part)
    .bind(password_hash)
    .bind("Active")
    .bind(Utc::now())
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

/// List mailboxes for a domain.
pub async fn list_mailboxes(
    pool: &SqlitePool,
    domain_id: i64,
) -> Result<Vec<Mailbox>, sqlx::Error> {
    sqlx::query_as::<_, Mailbox>("SELECT * FROM mailboxes WHERE domain_id = ? ORDER BY local_part")
        .bind(domain_id)
        .fetch_all(pool)
        .await
}

/// Get a single mailbox by ID.
pub async fn get_mailbox(pool: &SqlitePool, mailbox_id: i64) -> Result<Mailbox, sqlx::Error> {
    sqlx::query_as::<_, Mailbox>("SELECT * FROM mailboxes WHERE id = ?")
        .bind(mailbox_id)
        .fetch_one(pool)
        .await
}

/// Delete a mailbox.
pub async fn delete_mailbox(pool: &SqlitePool, mailbox_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM mailboxes WHERE id = ?")
        .bind(mailbox_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Create an email forwarder.
pub async fn create_forwarder(
    pool: &SqlitePool,
    domain_id: i64,
    local_part: String,
    forward_to: String,
) -> Result<i64, sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO email_forwarders (domain_id, local_part, forward_to, status, created_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(domain_id)
    .bind(local_part)
    .bind(forward_to)
    .bind("Active")
    .bind(Utc::now())
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

/// Delete an email forwarder.
pub async fn delete_forwarder(pool: &SqlitePool, forwarder_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM email_forwarders WHERE id = ?")
        .bind(forwarder_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Atomically check against rate limits and increment the send counter for a domain.
/// Returns `Ok(true)` if the send is allowed, `Ok(false)` if a limit is exceeded.
///
/// Uses `domain_send_counts` with sliding hour/day window keys so that counters
/// are reset automatically when the window changes — no background cleanup job needed.
pub async fn check_and_increment_send_count(
    pool: &SqlitePool,
    domain_id: i64,
) -> Result<bool, sqlx::Error> {
    let now = Utc::now();
    // Window keys: "YYYY-MM-DD-HH" and "YYYY-MM-DD"
    let hour_window = now.format("%Y-%m-%d-%H").to_string();
    let day_window = now.format("%Y-%m-%d").to_string();

    // Fetch domain send limits.
    let row: Option<(i32, i32)> = sqlx::query_as(
        "SELECT send_limit_per_hour, send_limit_per_day FROM email_domains WHERE id = ?",
    )
    .bind(domain_id)
    .fetch_optional(pool)
    .await?;

    let (limit_hour, limit_day) = match row {
        Some(r) => r,
        None => return Ok(true), // domain deleted race — allow
    };

    // Transactionally reset stale windows, read current counts, check, then increment.
    let mut tx = pool.begin().await?;

    // Upsert the counts row; reset whichever windows have rolled over.
    sqlx::query(
        "INSERT INTO domain_send_counts (domain_id, hourly_count, daily_count, hour_window, day_window)
         VALUES (?, 0, 0, ?, ?)
         ON CONFLICT(domain_id) DO UPDATE SET
           hourly_count = CASE WHEN hour_window = excluded.hour_window THEN hourly_count ELSE 0 END,
           daily_count  = CASE WHEN day_window  = excluded.day_window  THEN daily_count  ELSE 0 END,
           hour_window  = excluded.hour_window,
           day_window   = excluded.day_window",
    )
    .bind(domain_id)
    .bind(&hour_window)
    .bind(&day_window)
    .execute(&mut *tx)
    .await?;

    let (hourly_count, daily_count): (i64, i64) = sqlx::query_as(
        "SELECT hourly_count, daily_count FROM domain_send_counts WHERE domain_id = ?",
    )
    .bind(domain_id)
    .fetch_one(&mut *tx)
    .await?;

    if (limit_hour > 0 && hourly_count >= limit_hour as i64)
        || (limit_day > 0 && daily_count >= limit_day as i64)
    {
        tx.rollback().await?;
        return Ok(false);
    }

    // Increment both counters for this send.
    sqlx::query(
        "UPDATE domain_send_counts
         SET hourly_count = hourly_count + 1, daily_count = daily_count + 1
         WHERE domain_id = ?",
    )
    .bind(domain_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(true)
}

// ─── Catch-all ────────────────────────────────────────────────────────────────

/// Set or clear the catch-all address for a domain.
/// Pass `None` to disable catch-all.
pub async fn set_catch_all(
    pool: &SqlitePool,
    domain_id: i64,
    address: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE email_domains SET catch_all_address = ? WHERE id = ?")
        .bind(address)
        .bind(domain_id)
        .execute(pool)
        .await?;
    Ok(())
}

// ─── Plus-addressing ──────────────────────────────────────────────────────────

/// Enable or disable plus-addressing for a specific domain.
pub async fn set_plus_addressing(
    pool: &SqlitePool,
    domain_id: i64,
    enabled: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE email_domains SET plus_addressing_enabled = ? WHERE id = ?")
        .bind(enabled as i32)
        .bind(domain_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Returns `true` if any domain has plus-addressing enabled.
pub async fn any_plus_addressing_enabled(pool: &SqlitePool) -> Result<bool, sqlx::Error> {
    let row: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM email_domains WHERE plus_addressing_enabled = 1")
            .fetch_one(pool)
            .await?;
    Ok(row.0 > 0)
}

// ─── Regex forwarders ─────────────────────────────────────────────────────────

pub async fn create_regex_forwarder(
    pool: &SqlitePool,
    domain_id: i64,
    pattern: String,
    forward_to: String,
    description: Option<String>,
) -> Result<i64, sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO email_regex_forwarders (domain_id, pattern, forward_to, description, status, created_at)
         VALUES (?, ?, ?, ?, 'Active', ?)",
    )
    .bind(domain_id)
    .bind(pattern)
    .bind(forward_to)
    .bind(description)
    .bind(Utc::now())
    .execute(pool)
    .await?;
    Ok(result.last_insert_rowid())
}

pub async fn list_regex_forwarders(
    pool: &SqlitePool,
    domain_id: i64,
) -> Result<Vec<RegexForwarder>, sqlx::Error> {
    sqlx::query_as::<_, RegexForwarder>(
        "SELECT * FROM email_regex_forwarders WHERE domain_id = ? ORDER BY id",
    )
    .bind(domain_id)
    .fetch_all(pool)
    .await
}

/// Fetch every active regex forwarder across all domains (for rebuilding the regexp map).
pub async fn list_all_active_regex_forwarders(
    pool: &SqlitePool,
) -> Result<Vec<RegexForwarder>, sqlx::Error> {
    sqlx::query_as::<_, RegexForwarder>(
        "SELECT * FROM email_regex_forwarders WHERE status = 'Active' ORDER BY domain_id, id",
    )
    .fetch_all(pool)
    .await
}

pub async fn get_regex_forwarder(
    pool: &SqlitePool,
    id: i64,
) -> Result<RegexForwarder, sqlx::Error> {
    sqlx::query_as::<_, RegexForwarder>("SELECT * FROM email_regex_forwarders WHERE id = ?")
        .bind(id)
        .fetch_one(pool)
        .await
}

pub async fn delete_regex_forwarder(pool: &SqlitePool, id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM email_regex_forwarders WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

// ─── DKIM keys ─────────────────────────────────────────────────────────────────

pub async fn upsert_dkim_key(
    pool: &SqlitePool,
    domain_id: i64,
    domain: &str,
    selector: &str,
    public_key_dns: &str,
) -> Result<i64, sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO dkim_keys (domain_id, domain, selector, public_key_dns, status, created_at)
         VALUES (?, ?, ?, ?, 'Active', ?)
         ON CONFLICT(domain_id) DO UPDATE SET
           selector = excluded.selector,
           public_key_dns = excluded.public_key_dns,
           status = 'Active',
           created_at = excluded.created_at",
    )
    .bind(domain_id)
    .bind(domain)
    .bind(selector)
    .bind(public_key_dns)
    .bind(Utc::now())
    .execute(pool)
    .await?;
    Ok(result.last_insert_rowid())
}

pub async fn get_dkim_key(pool: &SqlitePool, domain_id: i64) -> Result<DkimKey, sqlx::Error> {
    sqlx::query_as::<_, DkimKey>("SELECT * FROM dkim_keys WHERE domain_id = ?")
        .bind(domain_id)
        .fetch_one(pool)
        .await
}

pub async fn list_all_dkim_keys(pool: &SqlitePool) -> Result<Vec<DkimKey>, sqlx::Error> {
    sqlx::query_as::<_, DkimKey>("SELECT * FROM dkim_keys WHERE status = 'Active' ORDER BY domain")
        .fetch_all(pool)
        .await
}

pub async fn delete_dkim_key(pool: &SqlitePool, domain_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM dkim_keys WHERE domain_id = ?")
        .bind(domain_id)
        .execute(pool)
        .await?;
    Ok(())
}
