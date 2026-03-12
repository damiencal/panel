/// FTP account database operations.
use chrono::Utc;
use sqlx::SqlitePool;

use crate::models::ftp::{FtpAccount, FtpAccountStats, FtpSessionStat};

/// Fetch an FTP account by ID.
pub async fn get(pool: &SqlitePool, account_id: i64) -> Result<FtpAccount, sqlx::Error> {
    sqlx::query_as::<_, FtpAccount>("SELECT * FROM ftp_accounts WHERE id = ?")
        .bind(account_id)
        .fetch_one(pool)
        .await
}

/// Fetch an FTP account by username.
pub async fn get_by_username(pool: &SqlitePool, username: &str) -> Result<FtpAccount, sqlx::Error> {
    sqlx::query_as::<_, FtpAccount>("SELECT * FROM ftp_accounts WHERE username = ?")
        .bind(username)
        .fetch_one(pool)
        .await
}

/// List FTP accounts for an owner.
pub async fn list_for_owner(
    pool: &SqlitePool,
    owner_id: i64,
) -> Result<Vec<FtpAccount>, sqlx::Error> {
    sqlx::query_as::<_, FtpAccount>(
        "SELECT * FROM ftp_accounts WHERE owner_id = ? ORDER BY username",
    )
    .bind(owner_id)
    .fetch_all(pool)
    .await
}

/// List FTP accounts for a site.
pub async fn list_for_site(
    pool: &SqlitePool,
    site_id: i64,
) -> Result<Vec<FtpAccount>, sqlx::Error> {
    sqlx::query_as::<_, FtpAccount>(
        "SELECT * FROM ftp_accounts WHERE site_id = ? ORDER BY username",
    )
    .bind(site_id)
    .fetch_all(pool)
    .await
}

/// Create a new FTP account.
pub async fn create(
    pool: &SqlitePool,
    owner_id: i64,
    site_id: Option<i64>,
    username: String,
    password_hash: String,
    home_dir: String,
    quota_size_mb: i64,
) -> Result<i64, sqlx::Error> {
    let now = Utc::now();
    let result = sqlx::query(
        "INSERT INTO ftp_accounts
            (owner_id, site_id, username, password_hash, home_dir, quota_size_mb, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, 'Active', ?, ?)",
    )
    .bind(owner_id)
    .bind(site_id)
    .bind(username)
    .bind(password_hash)
    .bind(home_dir)
    .bind(quota_size_mb)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

/// Update the password hash for an FTP account.
pub async fn update_password(
    pool: &SqlitePool,
    account_id: i64,
    password_hash: String,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE ftp_accounts SET password_hash = ?, updated_at = ? WHERE id = ?")
        .bind(password_hash)
        .bind(Utc::now())
        .bind(account_id)
        .execute(pool)
        .await
        .map(|_| ())
}

/// Update the status (Active/Suspended) of an FTP account.
pub async fn update_status(
    pool: &SqlitePool,
    account_id: i64,
    status: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE ftp_accounts SET status = ?, updated_at = ? WHERE id = ?")
        .bind(status)
        .bind(Utc::now())
        .bind(account_id)
        .execute(pool)
        .await
        .map(|_| ())
}

/// Delete an FTP account.
pub async fn delete(pool: &SqlitePool, account_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM ftp_accounts WHERE id = ?")
        .bind(account_id)
        .execute(pool)
        .await
        .map(|_| ())
}

// ── FTP session statistics ─────────────────────────────────────────────────

/// Insert a single transfer record parsed from the Pure-FTPd xferlog.
pub async fn insert_session_stat(
    pool: &SqlitePool,
    account_id: Option<i64>,
    username: &str,
    remote_host: Option<&str>,
    direction: &str,
    filename: &str,
    bytes_transferred: i64,
    transfer_time_secs: f64,
) -> Result<i64, sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO ftp_session_stats
            (account_id, username, remote_host, direction, filename,
             bytes_transferred, transfer_time_secs, completed_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(account_id)
    .bind(username)
    .bind(remote_host)
    .bind(direction)
    .bind(filename)
    .bind(bytes_transferred)
    .bind(transfer_time_secs)
    .bind(Utc::now())
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

/// Fetch the N most recent transfer records for a given owner.
pub async fn list_recent_stats(
    pool: &SqlitePool,
    owner_id: i64,
    limit: i64,
) -> Result<Vec<FtpSessionStat>, sqlx::Error> {
    sqlx::query_as::<_, FtpSessionStat>(
        "SELECT s.*
         FROM ftp_session_stats s
         JOIN ftp_accounts a ON a.username = s.username AND a.owner_id = ?
         ORDER BY s.completed_at DESC
         LIMIT ?",
    )
    .bind(owner_id)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Per-account aggregated stats for all accounts belonging to an owner.
pub async fn aggregate_per_account(
    pool: &SqlitePool,
    owner_id: i64,
) -> Result<Vec<FtpAccountStats>, sqlx::Error> {
    #[derive(sqlx::FromRow)]
    struct Row {
        username: String,
        total_uploads: i64,
        total_downloads: i64,
        bytes_uploaded: i64,
        bytes_downloaded: i64,
        last_active: Option<String>,
    }

    // Use a LEFT JOIN so accounts with zero transfers still appear.
    let rows = sqlx::query_as::<_, Row>(
        r#"
        SELECT
            a.username,
            COALESCE(SUM(CASE WHEN s.direction = 'Upload' THEN 1 ELSE 0 END), 0)   AS total_uploads,
            COALESCE(SUM(CASE WHEN s.direction = 'Download' THEN 1 ELSE 0 END), 0) AS total_downloads,
            COALESCE(SUM(CASE WHEN s.direction = 'Upload' THEN s.bytes_transferred ELSE 0 END), 0)   AS bytes_uploaded,
            COALESCE(SUM(CASE WHEN s.direction = 'Download' THEN s.bytes_transferred ELSE 0 END), 0) AS bytes_downloaded,
            MAX(s.completed_at) AS last_active
        FROM ftp_accounts a
        LEFT JOIN ftp_session_stats s ON s.username = a.username
        WHERE a.owner_id = ?
        GROUP BY a.username
        ORDER BY a.username
        "#,
    )
    .bind(owner_id)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| FtpAccountStats {
            username: r.username,
            total_uploads: r.total_uploads,
            total_downloads: r.total_downloads,
            bytes_uploaded: r.bytes_uploaded,
            bytes_downloaded: r.bytes_downloaded,
            last_active: r.last_active.as_deref().and_then(|ts| {
                chrono::DateTime::parse_from_rfc3339(ts)
                    .ok()
                    .map(|dt| dt.with_timezone(&Utc))
            }),
        })
        .collect())
}

/// Count active (status = 'Active') FTP accounts for an owner.
pub async fn count_active(pool: &SqlitePool, owner_id: i64) -> Result<i64, sqlx::Error> {
    let (cnt,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM ftp_accounts WHERE owner_id = ? AND status = 'Active'",
    )
    .bind(owner_id)
    .fetch_one(pool)
    .await?;
    Ok(cnt)
}

/// Count total FTP accounts for an owner.
pub async fn count_total(pool: &SqlitePool, owner_id: i64) -> Result<i64, sqlx::Error> {
    let (cnt,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM ftp_accounts WHERE owner_id = ?")
        .bind(owner_id)
        .fetch_one(pool)
        .await?;
    Ok(cnt)
}
