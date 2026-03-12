/// Reseller branding database operations.
use chrono::Utc;
use sqlx::SqlitePool;

pub use crate::models::branding::ResellerBranding;

/// Get branding for a reseller.
pub async fn get(
    pool: &SqlitePool,
    reseller_id: i64,
) -> Result<Option<ResellerBranding>, sqlx::Error> {
    sqlx::query_as::<_, ResellerBranding>("SELECT * FROM reseller_branding WHERE reseller_id = ?")
        .bind(reseller_id)
        .fetch_optional(pool)
        .await
}

/// Get branding by custom domain (used for public-facing hostname lookup, no auth required).
pub async fn get_by_domain(
    pool: &SqlitePool,
    custom_domain: &str,
) -> Result<Option<ResellerBranding>, sqlx::Error> {
    sqlx::query_as::<_, ResellerBranding>("SELECT * FROM reseller_branding WHERE custom_domain = ?")
        .bind(custom_domain)
        .fetch_optional(pool)
        .await
}

/// Upsert branding for a reseller.
pub async fn upsert(
    pool: &SqlitePool,
    reseller_id: i64,
    panel_name: String,
    logo_path: Option<String>,
    accent_color: String,
    custom_domain: Option<String>,
    custom_ns1: Option<String>,
    custom_ns2: Option<String>,
    footer_text: Option<String>,
    theme_preset: String,
) -> Result<i64, sqlx::Error> {
    let now = Utc::now().to_rfc3339();
    let result = sqlx::query(
        "INSERT INTO reseller_branding
            (reseller_id, panel_name, logo_path, accent_color, custom_domain,
             custom_ns1, custom_ns2, footer_text, theme_preset, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(reseller_id) DO UPDATE SET
            panel_name    = excluded.panel_name,
            logo_path     = excluded.logo_path,
            accent_color  = excluded.accent_color,
            custom_domain = excluded.custom_domain,
            custom_ns1    = excluded.custom_ns1,
            custom_ns2    = excluded.custom_ns2,
            footer_text   = excluded.footer_text,
            theme_preset  = excluded.theme_preset,
            updated_at    = excluded.updated_at",
    )
    .bind(reseller_id)
    .bind(panel_name)
    .bind(logo_path)
    .bind(accent_color)
    .bind(custom_domain)
    .bind(custom_ns1)
    .bind(custom_ns2)
    .bind(footer_text)
    .bind(theme_preset)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

/// Delete branding for a reseller.
pub async fn delete(pool: &SqlitePool, reseller_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM reseller_branding WHERE reseller_id = ?")
        .bind(reseller_id)
        .execute(pool)
        .await?;
    Ok(())
}
