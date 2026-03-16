/// Database operations for team invitations and per-site developer access grants.
use crate::models::team::TeamInvitation;
use crate::models::user::User;
use chrono::Utc;
use sqlx::SqlitePool;

/// Create a new invitation record.
/// `token_hash` is the SHA-256 hex of the raw one-time token; the raw token
/// is never stored in the database.
pub async fn create_invitation(
    pool: &SqlitePool,
    client_id: i64,
    email: &str,
    token_hash: &str,
    site_ids_json: &str,
    expires_at: chrono::DateTime<Utc>,
) -> Result<i64, sqlx::Error> {
    let now = Utc::now();
    let result = sqlx::query(
        "INSERT INTO team_invitations
             (client_id, email, token_hash, site_ids, expires_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(client_id)
    .bind(email)
    .bind(token_hash)
    .bind(site_ids_json)
    .bind(expires_at)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(result.last_insert_rowid())
}

/// Look up an invitation by its SHA-256 token hash.
pub async fn get_by_token_hash(
    pool: &SqlitePool,
    token_hash: &str,
) -> Result<Option<TeamInvitation>, sqlx::Error> {
    sqlx::query_as::<_, TeamInvitation>("SELECT * FROM team_invitations WHERE token_hash = ?")
        .bind(token_hash)
        .fetch_optional(pool)
        .await
}

/// List all invitations created by a client, newest first.
pub async fn list_invitations(
    pool: &SqlitePool,
    client_id: i64,
) -> Result<Vec<TeamInvitation>, sqlx::Error> {
    sqlx::query_as::<_, TeamInvitation>(
        "SELECT * FROM team_invitations WHERE client_id = ? ORDER BY created_at DESC",
    )
    .bind(client_id)
    .fetch_all(pool)
    .await
}

/// Mark an invitation as consumed by setting `consumed_at` to now.
pub async fn consume_invitation(pool: &SqlitePool, id: i64) -> Result<(), sqlx::Error> {
    let now = Utc::now();
    sqlx::query("UPDATE team_invitations SET consumed_at = ? WHERE id = ?")
        .bind(now)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Delete an invitation record (revoke before consumption).
pub async fn revoke_invitation(pool: &SqlitePool, id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM team_invitations WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Grant a developer access to a specific site.
/// Uses `INSERT OR IGNORE` so repeated calls are safe.
pub async fn grant_site_access(
    pool: &SqlitePool,
    developer_id: i64,
    site_id: i64,
) -> Result<(), sqlx::Error> {
    let now = Utc::now();
    sqlx::query(
        "INSERT OR IGNORE INTO team_site_access (developer_id, site_id, granted_at)
         VALUES (?, ?, ?)",
    )
    .bind(developer_id)
    .bind(site_id)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// Revoke a developer's access to a specific site.
pub async fn revoke_site_access(
    pool: &SqlitePool,
    developer_id: i64,
    site_id: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM team_site_access WHERE developer_id = ? AND site_id = ?")
        .bind(developer_id)
        .bind(site_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Return all site IDs a developer has been granted access to.
pub async fn get_developer_sites(
    pool: &SqlitePool,
    developer_id: i64,
) -> Result<Vec<i64>, sqlx::Error> {
    let rows: Vec<(i64,)> =
        sqlx::query_as("SELECT site_id FROM team_site_access WHERE developer_id = ?")
            .bind(developer_id)
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}

/// Return all Developer users whose `parent_id` matches `client_id`.
pub async fn list_developers(pool: &SqlitePool, client_id: i64) -> Result<Vec<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE parent_id = ? AND role = 'Developer'
         ORDER BY created_at DESC",
    )
    .bind(client_id)
    .fetch_all(pool)
    .await
}

/// Check whether `developer_id` has been granted access to `site_id`.
pub async fn has_site_access(
    pool: &SqlitePool,
    developer_id: i64,
    site_id: i64,
) -> Result<bool, sqlx::Error> {
    let row: Option<(i64,)> = sqlx::query_as(
        "SELECT developer_id FROM team_site_access
         WHERE developer_id = ? AND site_id = ?",
    )
    .bind(developer_id)
    .bind(site_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some())
}
