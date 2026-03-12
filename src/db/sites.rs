/// Website/site database operations.
use crate::models::site::{Site, SiteStatus, SiteType};
use chrono::Utc;
use sqlx::SqlitePool;

/// Get a site by ID.
pub async fn get(pool: &SqlitePool, site_id: i64) -> Result<Site, sqlx::Error> {
    sqlx::query_as::<_, Site>("SELECT * FROM sites WHERE id = ?")
        .bind(site_id)
        .fetch_one(pool)
        .await
}

/// Get a site by domain name.
pub async fn get_by_domain(pool: &SqlitePool, domain: &str) -> Result<Site, sqlx::Error> {
    sqlx::query_as::<_, Site>("SELECT * FROM sites WHERE domain = ?")
        .bind(domain)
        .fetch_one(pool)
        .await
}

/// List sites for an owner.
pub async fn list_for_owner(pool: &SqlitePool, owner_id: i64) -> Result<Vec<Site>, sqlx::Error> {
    sqlx::query_as::<_, Site>("SELECT * FROM sites WHERE owner_id = ? ORDER BY domain")
        .bind(owner_id)
        .fetch_all(pool)
        .await
}

/// List sites for a reseller's clients.
pub async fn list_for_reseller(
    pool: &SqlitePool,
    reseller_id: i64,
) -> Result<Vec<Site>, sqlx::Error> {
    sqlx::query_as::<_, Site>(
        "SELECT s.* FROM sites s
         INNER JOIN users u ON s.owner_id = u.id
         WHERE u.parent_id = ?
         ORDER BY s.domain",
    )
    .bind(reseller_id)
    .fetch_all(pool)
    .await
}

/// List all sites (Admin only).
pub async fn list_all(pool: &SqlitePool) -> Result<Vec<Site>, sqlx::Error> {
    sqlx::query_as::<_, Site>("SELECT * FROM sites ORDER BY domain")
        .fetch_all(pool)
        .await
}

/// Create a new site.
pub async fn create(
    pool: &SqlitePool,
    owner_id: i64,
    domain: String,
    doc_root: String,
    site_type: SiteType,
) -> Result<i64, sqlx::Error> {
    let now = Utc::now();
    let ols_vhost_name = format!("vhost_{}", domain.replace(".", "_"));
    let result = sqlx::query(
        "INSERT INTO sites (owner_id, domain, doc_root, site_type, status, 
            ols_vhost_name, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(owner_id)
    .bind(domain)
    .bind(doc_root)
    .bind(site_type)
    .bind(SiteStatus::Active)
    .bind(ols_vhost_name)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

/// Update site status.
pub async fn update_status(
    pool: &SqlitePool,
    site_id: i64,
    status: SiteStatus,
) -> Result<(), sqlx::Error> {
    let now = Utc::now();
    sqlx::query("UPDATE sites SET status = ?, updated_at = ? WHERE id = ?")
        .bind(status)
        .bind(now)
        .bind(site_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Update SSL and HSTS settings for a site.
#[allow(clippy::too_many_arguments)]
pub async fn update_ssl(
    pool: &SqlitePool,
    site_id: i64,
    ssl_enabled: bool,
    force_https: bool,
    hsts_enabled: bool,
    hsts_max_age: i64,
    hsts_include_subdomains: bool,
    hsts_preload: bool,
) -> Result<(), sqlx::Error> {
    // HSTS only makes sense when both SSL and HTTPS redirect are active.
    let effective_hsts = hsts_enabled && ssl_enabled && force_https;
    // preload requires the caller to explicitly request it AND includeSubDomains
    // AND a max-age of at least 1 year (31536000 seconds).
    let effective_preload =
        effective_hsts && hsts_preload && hsts_include_subdomains && hsts_max_age >= 31536000;
    let now = Utc::now();
    sqlx::query(
        "UPDATE sites
         SET ssl_enabled = ?, force_https = ?,
             hsts_enabled = ?, hsts_max_age = ?,
             hsts_include_subdomains = ?, hsts_preload = ?,
             updated_at = ?
         WHERE id = ?",
    )
    .bind(ssl_enabled)
    .bind(force_https)
    .bind(effective_hsts)
    .bind(hsts_max_age)
    .bind(hsts_include_subdomains)
    .bind(effective_preload)
    .bind(now)
    .bind(site_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Update site type.
pub async fn update_site_type(
    pool: &SqlitePool,
    site_id: i64,
    site_type: SiteType,
) -> Result<(), sqlx::Error> {
    let now = Utc::now();
    sqlx::query("UPDATE sites SET site_type = ?, updated_at = ? WHERE id = ?")
        .bind(site_type)
        .bind(now)
        .bind(site_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Delete a site.
pub async fn delete(pool: &SqlitePool, site_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM sites WHERE id = ?")
        .bind(site_id)
        .execute(pool)
        .await?;
    Ok(())
}
