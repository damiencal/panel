/// Resource quota database operations.
use crate::models::quota::{ResourceQuota, ResourceUsage};
use chrono::Utc;
use sqlx::SqlitePool;

/// Get quota for a user.
pub async fn get_quota(pool: &SqlitePool, user_id: i64) -> Result<ResourceQuota, sqlx::Error> {
    sqlx::query_as::<_, ResourceQuota>("SELECT * FROM resource_quotas WHERE user_id = ?")
        .bind(user_id)
        .fetch_one(pool)
        .await
}

/// Get usage for a user.
pub async fn get_usage(pool: &SqlitePool, user_id: i64) -> Result<ResourceUsage, sqlx::Error> {
    sqlx::query_as::<_, ResourceUsage>("SELECT * FROM resource_usage WHERE user_id = ?")
        .bind(user_id)
        .fetch_one(pool)
        .await
}

/// Allocate quota to a user.
#[allow(clippy::too_many_arguments)]
pub async fn allocate_quota(
    pool: &SqlitePool,
    user_id: i64,
    max_clients: Option<i32>,
    max_sites: i32,
    max_databases: i32,
    max_email_accounts: i32,
    disk_limit_mb: i64,
    bandwidth_limit_mb: i64,
) -> Result<i64, sqlx::Error> {
    let now = Utc::now();
    let result = sqlx::query(
        "INSERT INTO resource_quotas (user_id, max_clients, max_sites, max_databases, 
            max_email_accounts, disk_limit_mb, bandwidth_limit_mb, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(user_id) DO UPDATE SET
            max_clients=excluded.max_clients, max_sites=excluded.max_sites,
            max_databases=excluded.max_databases, max_email_accounts=excluded.max_email_accounts,
            disk_limit_mb=excluded.disk_limit_mb, bandwidth_limit_mb=excluded.bandwidth_limit_mb,
            updated_at=excluded.updated_at",
    )
    .bind(user_id)
    .bind(max_clients)
    .bind(max_sites)
    .bind(max_databases)
    .bind(max_email_accounts)
    .bind(disk_limit_mb)
    .bind(bandwidth_limit_mb)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

/// Initialize usage tracking for a user.
pub async fn init_usage(pool: &SqlitePool, user_id: i64) -> Result<i64, sqlx::Error> {
    let result = sqlx::query(
        "INSERT OR IGNORE INTO resource_usage (user_id, sites_used, databases_used, 
            email_accounts_used, disk_used_mb, bandwidth_used_mb, updated_at)
         VALUES (?, 0, 0, 0, 0, 0, ?)",
    )
    .bind(user_id)
    .bind(Utc::now())
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

/// Update site count for a user.
pub async fn increment_sites(
    pool: &SqlitePool,
    user_id: i64,
    amount: i32,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE resource_usage SET sites_used = sites_used + ?, updated_at = ? WHERE user_id = ?",
    )
    .bind(amount)
    .bind(Utc::now())
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Update database count for a user.
pub async fn increment_databases(
    pool: &SqlitePool,
    user_id: i64,
    amount: i32,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE resource_usage SET databases_used = databases_used + ?, updated_at = ? WHERE user_id = ?"
    )
    .bind(amount)
    .bind(Utc::now())
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Update email account count for a user.
pub async fn increment_email_accounts(
    pool: &SqlitePool,
    user_id: i64,
    amount: i32,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE resource_usage SET email_accounts_used = email_accounts_used + ?, updated_at = ? WHERE user_id = ?"
    )
    .bind(amount)
    .bind(Utc::now())
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}

// ─── Quota enforcement helpers ────────────────────────────────────────────────
//
// Each helper loads the quota and usage rows for a user and returns `Ok(())`
// when the operation is allowed, or `Err(String)` with a user-visible message
// when the limit is reached.
//
// If no quota row exists the operation is allowed (new users without an
// explicit allocation default to unrestricted).

/// Check whether a user may create an additional site.
pub async fn check_can_create_site(pool: &SqlitePool, user_id: i64) -> Result<(), String> {
    let quota = match get_quota(pool, user_id).await {
        Ok(q) => q,
        Err(sqlx::Error::RowNotFound) => return Ok(()),
        Err(e) => return Err(format!("Failed to check quota: {}", e)),
    };

    if quota.max_sites <= 0 {
        return Ok(()); // 0 or negative means unlimited
    }

    let usage = match get_usage(pool, user_id).await {
        Ok(u) => u,
        Err(sqlx::Error::RowNotFound) => return Ok(()),
        Err(e) => return Err(format!("Failed to check usage: {}", e)),
    };

    if usage.sites_used >= quota.max_sites {
        return Err(format!(
            "Site limit reached ({}/{} used). Please contact support to increase your limit.",
            usage.sites_used, quota.max_sites
        ));
    }

    Ok(())
}

/// Check whether a user may create an additional database.
pub async fn check_can_create_database(pool: &SqlitePool, user_id: i64) -> Result<(), String> {
    let quota = match get_quota(pool, user_id).await {
        Ok(q) => q,
        Err(sqlx::Error::RowNotFound) => return Ok(()),
        Err(e) => return Err(format!("Failed to check quota: {}", e)),
    };

    if quota.max_databases <= 0 {
        return Ok(());
    }

    let usage = match get_usage(pool, user_id).await {
        Ok(u) => u,
        Err(sqlx::Error::RowNotFound) => return Ok(()),
        Err(e) => return Err(format!("Failed to check usage: {}", e)),
    };

    if usage.databases_used >= quota.max_databases {
        return Err(format!(
            "Database limit reached ({}/{} used). Please contact support to increase your limit.",
            usage.databases_used, quota.max_databases
        ));
    }

    Ok(())
}

/// Check whether a user may create an additional database **and** atomically increment
/// the counter if allowed.  Eliminates the TOCTOU race present in the separate
/// check-then-increment pattern used elsewhere.
///
/// On success the `databases_used` counter has already been incremented.  If the
/// subsequent database provisioning fails the caller is responsible for rolling back
/// with `increment_databases(pool, user_id, -1)`.
pub async fn check_and_increment_databases(pool: &SqlitePool, user_id: i64) -> Result<(), String> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| format!("Transaction error: {e}"))?;

    let row: Option<(i32, i32)> = sqlx::query_as(
        "SELECT q.max_databases, COALESCE(u.databases_used, 0)
         FROM resource_quotas q
         LEFT JOIN resource_usage u ON u.user_id = q.user_id
         WHERE q.user_id = ?",
    )
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| format!("Failed to check quota: {e}"))?;

    if let Some((max_databases, databases_used)) = row {
        if max_databases > 0 && databases_used >= max_databases {
            return Err(format!(
                "Database limit reached ({}/{} used). Please contact support to increase your limit.",
                databases_used, max_databases
            ));
        }
    }

    let updated = sqlx::query(
        "UPDATE resource_usage
         SET databases_used = databases_used + 1, updated_at = ?
         WHERE user_id = ?",
    )
    .bind(Utc::now())
    .bind(user_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("Failed to increment database count: {e}"))?;

    if updated.rows_affected() == 0 {
        tx.rollback().await.ok();
        return Err(format!(
            "Usage tracking row missing for user {user_id} — \
             run init_usage before allocating resources"
        ));
    }

    tx.commit()
        .await
        .map_err(|e| format!("Commit failed: {e}"))?;

    Ok(())
}

/// Check whether a user may create an additional email account (mailbox).
pub async fn check_can_create_email_account(pool: &SqlitePool, user_id: i64) -> Result<(), String> {
    let quota = match get_quota(pool, user_id).await {
        Ok(q) => q,
        Err(sqlx::Error::RowNotFound) => return Ok(()),
        Err(e) => return Err(format!("Failed to check quota: {}", e)),
    };

    if quota.max_email_accounts <= 0 {
        return Ok(());
    }

    let usage = match get_usage(pool, user_id).await {
        Ok(u) => u,
        Err(sqlx::Error::RowNotFound) => return Ok(()),
        Err(e) => return Err(format!("Failed to check usage: {}", e)),
    };

    if usage.email_accounts_used >= quota.max_email_accounts {
        return Err(format!(
            "Email account limit reached ({}/{} used). Please contact support to increase your limit.",
            usage.email_accounts_used, quota.max_email_accounts
        ));
    }

    Ok(())
}

/// Check whether a user may create an additional site **and** atomically increment
/// the counter if allowed.  Both the read and the write happen inside a single
/// SQLite transaction, which eliminates the TOCTOU race present in the separate
/// check-then-increment pattern used elsewhere.
///
/// On success the `sites_used` counter has already been incremented.  If the
/// subsequent site-creation call fails the caller is responsible for rolling back
/// with `increment_sites(pool, user_id, -1)`.
pub async fn check_and_increment_sites(pool: &SqlitePool, user_id: i64) -> Result<(), String> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| format!("Transaction error: {e}"))?;

    // Read quota and current usage within the same write transaction so that
    // SQLite's serialised writer lock prevents two concurrent requests from
    // both passing the quota check before either increments the counter.
    let row: Option<(i32, i32)> = sqlx::query_as(
        "SELECT q.max_sites, COALESCE(u.sites_used, 0)
         FROM resource_quotas q
         LEFT JOIN resource_usage u ON u.user_id = q.user_id
         WHERE q.user_id = ?",
    )
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| format!("Failed to check quota: {e}"))?;

    if let Some((max_sites, sites_used)) = row {
        if max_sites > 0 && sites_used >= max_sites {
            return Err(format!(
                "Site limit reached ({}/{} used). Please contact support to increase your limit.",
                sites_used, max_sites
            ));
        }
    }
    // No quota row ⇒ no limit — proceed.

    let updated = sqlx::query(
        "UPDATE resource_usage SET sites_used = sites_used + 1, updated_at = ? WHERE user_id = ?",
    )
    .bind(Utc::now())
    .bind(user_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("Failed to increment site count: {e}"))?;

    if updated.rows_affected() == 0 {
        tx.rollback().await.ok();
        return Err(format!(
            "Usage tracking row missing for user {user_id} — \
             run init_usage before allocating resources"
        ));
    }

    tx.commit()
        .await
        .map_err(|e| format!("Commit failed: {e}"))?;

    Ok(())
}

/// Check whether a user may create an additional email account **and** atomically increment
/// the counter if allowed.  Eliminates the TOCTOU race present in the separate
/// check-then-increment pattern.
///
/// On success the `email_accounts_used` counter has already been incremented.  If the
/// subsequent mailbox creation fails the caller is responsible for rolling back
/// with `increment_email_accounts(pool, user_id, -1)`.
pub async fn check_and_increment_email_accounts(
    pool: &SqlitePool,
    user_id: i64,
) -> Result<(), String> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| format!("Transaction error: {e}"))?;

    let row: Option<(i32, i32)> = sqlx::query_as(
        "SELECT q.max_email_accounts, COALESCE(u.email_accounts_used, 0)
         FROM resource_quotas q
         LEFT JOIN resource_usage u ON u.user_id = q.user_id
         WHERE q.user_id = ?",
    )
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| format!("Failed to check quota: {e}"))?;

    if let Some((max_accounts, accounts_used)) = row {
        if max_accounts > 0 && accounts_used >= max_accounts {
            return Err(format!(
                "Email account limit reached ({}/{} used). Please contact support to increase your limit.",
                accounts_used, max_accounts
            ));
        }
    }

    let updated = sqlx::query(
        "UPDATE resource_usage
         SET email_accounts_used = email_accounts_used + 1, updated_at = ?
         WHERE user_id = ?",
    )
    .bind(Utc::now())
    .bind(user_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("Failed to increment email account count: {e}"))?;

    if updated.rows_affected() == 0 {
        tx.rollback().await.ok();
        return Err(format!(
            "Usage tracking row missing for user {user_id} — \
             run init_usage before allocating resources"
        ));
    }

    tx.commit()
        .await
        .map_err(|e| format!("Commit failed: {e}"))?;

    Ok(())
}

/// Returns the percentage (0–100) of a resource limit that has been used.
/// Returns 0 if the limit is 0 or negative (unlimited).
pub fn usage_percent(used: i32, limit: i32) -> u32 {
    if limit <= 0 {
        return 0;
    }
    ((used as f64 / limit as f64) * 100.0).round() as u32
}
