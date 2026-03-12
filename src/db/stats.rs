/// Web statistics database operations.
use crate::models::stats::{StatsConfig, StatsRunStatus, StatsTool};
use chrono::Utc;
use sqlx::SqlitePool;

/// Return all stats configs for a specific site.
pub async fn list_for_site(
    pool: &SqlitePool,
    site_id: i64,
) -> Result<Vec<StatsConfig>, sqlx::Error> {
    sqlx::query_as::<_, StatsConfig>(
        "SELECT * FROM web_stats_configs WHERE site_id = ? ORDER BY tool",
    )
    .bind(site_id)
    .fetch_all(pool)
    .await
}

/// Return all stats configs for every site owned by a user.
pub async fn list_for_owner(
    pool: &SqlitePool,
    owner_id: i64,
) -> Result<Vec<StatsConfig>, sqlx::Error> {
    sqlx::query_as::<_, StatsConfig>(
        "SELECT wsc.* FROM web_stats_configs wsc
         INNER JOIN sites s ON wsc.site_id = s.id
         WHERE s.owner_id = ?
         ORDER BY wsc.domain, wsc.tool",
    )
    .bind(owner_id)
    .fetch_all(pool)
    .await
}

/// Return all stats configs (admin view).
pub async fn list_all(pool: &SqlitePool) -> Result<Vec<StatsConfig>, sqlx::Error> {
    sqlx::query_as::<_, StatsConfig>("SELECT * FROM web_stats_configs ORDER BY domain, tool")
        .fetch_all(pool)
        .await
}

/// Get a single config by ID.
pub async fn get(pool: &SqlitePool, id: i64) -> Result<StatsConfig, sqlx::Error> {
    sqlx::query_as::<_, StatsConfig>("SELECT * FROM web_stats_configs WHERE id = ?")
        .bind(id)
        .fetch_one(pool)
        .await
}

/// Get a config by site_id + tool, or None if absent.
pub async fn get_for_site_tool(
    pool: &SqlitePool,
    site_id: i64,
    tool: StatsTool,
) -> Result<Option<StatsConfig>, sqlx::Error> {
    sqlx::query_as::<_, StatsConfig>(
        "SELECT * FROM web_stats_configs WHERE site_id = ? AND tool = ?",
    )
    .bind(site_id)
    .bind(tool)
    .fetch_optional(pool)
    .await
}

/// Insert a new stats config (or ignore if already present), then return it.
pub async fn ensure_config(
    pool: &SqlitePool,
    site_id: i64,
    domain: &str,
    tool: StatsTool,
    output_dir: &str,
) -> Result<i64, sqlx::Error> {
    let now = Utc::now();
    let result = sqlx::query(
        "INSERT INTO web_stats_configs
             (site_id, domain, tool, enabled, output_dir, created_at, updated_at)
         VALUES (?, ?, ?, TRUE, ?, ?, ?)
         ON CONFLICT (site_id, tool) DO NOTHING",
    )
    .bind(site_id)
    .bind(domain)
    .bind(tool)
    .bind(output_dir)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    if result.last_insert_rowid() != 0 {
        return Ok(result.last_insert_rowid());
    }

    // Already existed — return its id
    let row: (i64,) =
        sqlx::query_as("SELECT id FROM web_stats_configs WHERE site_id = ? AND tool = ?")
            .bind(site_id)
            .bind(tool)
            .fetch_one(pool)
            .await?;
    Ok(row.0)
}

/// Toggle enabled flag for a config.
pub async fn set_enabled(pool: &SqlitePool, id: i64, enabled: bool) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE web_stats_configs SET enabled = ?, updated_at = ? WHERE id = ?")
        .bind(enabled)
        .bind(Utc::now())
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Record the outcome of a stats run.
pub async fn record_run(
    pool: &SqlitePool,
    id: i64,
    status: StatsRunStatus,
    error: Option<&str>,
) -> Result<(), sqlx::Error> {
    let now = Utc::now();
    sqlx::query(
        "UPDATE web_stats_configs
         SET last_run_at = ?, last_status = ?, last_error = ?, updated_at = ?
         WHERE id = ?",
    )
    .bind(now)
    .bind(status)
    .bind(error)
    .bind(now)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}
