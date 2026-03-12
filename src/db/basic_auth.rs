/// Database operations for per-site HTTP Basic Authentication users.
use crate::models::site::BasicAuthUser;
use sqlx::SqlitePool;

/// List all Basic Auth users for a site.
pub async fn list_users(
    pool: &SqlitePool,
    site_id: i64,
) -> Result<Vec<BasicAuthUser>, sqlx::Error> {
    sqlx::query_as::<_, BasicAuthUser>(
        "SELECT * FROM basic_auth_users WHERE site_id = ? ORDER BY username",
    )
    .bind(site_id)
    .fetch_all(pool)
    .await
}

/// Add a new Basic Auth user.  The caller is responsible for uniqueness
/// enforcement — if the username already exists for the site the DB unique
/// constraint will return an error.
pub async fn add_user(
    pool: &SqlitePool,
    site_id: i64,
    username: &str,
    password_hash: &str,
) -> Result<(), sqlx::Error> {
    let now = chrono::Utc::now();
    sqlx::query(
        "INSERT INTO basic_auth_users (site_id, username, password_hash, created_at)
         VALUES (?, ?, ?, ?)",
    )
    .bind(site_id)
    .bind(username)
    .bind(password_hash)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// Remove a Basic Auth user by site and username.
pub async fn remove_user(
    pool: &SqlitePool,
    site_id: i64,
    username: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM basic_auth_users WHERE site_id = ? AND username = ?")
        .bind(site_id)
        .bind(username)
        .execute(pool)
        .await?;
    Ok(())
}

/// Check whether a username already exists for a site.
pub async fn user_exists(
    pool: &SqlitePool,
    site_id: i64,
    username: &str,
) -> Result<bool, sqlx::Error> {
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM basic_auth_users WHERE site_id = ? AND username = ?",
    )
    .bind(site_id)
    .bind(username)
    .fetch_one(pool)
    .await?;
    Ok(row.0 > 0)
}
