/// User database operations.
use crate::models::user::{AccountStatus, Role, User};
use chrono::Utc;
use sqlx::SqlitePool;

/// Get a user by ID.
pub async fn get(pool: &SqlitePool, user_id: i64) -> Result<User, sqlx::Error> {
    sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_one(pool)
        .await
}

/// Get a user by username.
pub async fn get_by_username(pool: &SqlitePool, username: &str) -> Result<User, sqlx::Error> {
    sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = ?")
        .bind(username)
        .fetch_one(pool)
        .await
}

/// Get a user by email.
pub async fn get_by_email(pool: &SqlitePool, email: &str) -> Result<User, sqlx::Error> {
    sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = ?")
        .bind(email)
        .fetch_one(pool)
        .await
}

/// List all users (Admin only).
pub async fn list_all(pool: &SqlitePool) -> Result<Vec<User>, sqlx::Error> {
    sqlx::query_as::<_, User>("SELECT * FROM users ORDER BY created_at DESC")
        .fetch_all(pool)
        .await
}

/// List clients for a reseller.
pub async fn list_clients_for_reseller(
    pool: &SqlitePool,
    reseller_id: i64,
) -> Result<Vec<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE role = 'Client' AND parent_id = ? ORDER BY created_at DESC",
    )
    .bind(reseller_id)
    .fetch_all(pool)
    .await
}

/// List resellers (Admin only).
pub async fn list_resellers(pool: &SqlitePool) -> Result<Vec<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE role = 'Reseller' ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await
}

/// Count clients belonging to a reseller.
pub async fn count_clients_for_reseller(
    pool: &SqlitePool,
    reseller_id: i64,
) -> Result<i64, sqlx::Error> {
    let row: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM users WHERE role = 'Client' AND parent_id = ?")
            .bind(reseller_id)
            .fetch_one(pool)
            .await?;
    Ok(row.0)
}

/// Create a new user.
pub async fn create(
    pool: &SqlitePool,
    username: String,
    email: String,
    password_hash: String,
    role: Role,
    parent_id: Option<i64>,
    package_id: Option<i64>,
) -> Result<i64, sqlx::Error> {
    let now = Utc::now();
    let result = sqlx::query(
        "INSERT INTO users (username, email, password_hash, role, parent_id, package_id, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(username)
    .bind(email)
    .bind(password_hash)
    .bind(role)
    .bind(parent_id)
    .bind(package_id)
    .bind(AccountStatus::Active)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

/// Update user status.
pub async fn update_status(
    pool: &SqlitePool,
    user_id: i64,
    status: AccountStatus,
) -> Result<(), sqlx::Error> {
    let now = Utc::now();
    sqlx::query("UPDATE users SET status = ?, updated_at = ? WHERE id = ?")
        .bind(status)
        .bind(now)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Update password hash.
pub async fn update_password(
    pool: &SqlitePool,
    user_id: i64,
    password_hash: String,
) -> Result<(), sqlx::Error> {
    let now = Utc::now();
    sqlx::query(
        "UPDATE users SET password_hash = ?, password_changed_at = ?, updated_at = ? WHERE id = ?",
    )
    .bind(password_hash)
    .bind(now)
    .bind(now)
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Enable 2FA for a user.
pub async fn enable_totp(
    pool: &SqlitePool,
    user_id: i64,
    totp_secret: String,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?")
        .bind(totp_secret)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Disable 2FA for a user.
pub async fn disable_totp(pool: &SqlitePool, user_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE id = ?")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Update a user's contact detail fields (company, address, phone).
pub async fn update_details(
    pool: &SqlitePool,
    user_id: i64,
    company: Option<String>,
    address: Option<String>,
    phone: Option<String>,
) -> Result<(), sqlx::Error> {
    let now = chrono::Utc::now();
    sqlx::query(
        "UPDATE users SET company = ?, address = ?, phone = ?, updated_at = ? WHERE id = ?",
    )
    .bind(company)
    .bind(address)
    .bind(phone)
    .bind(now)
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Delete a user.
pub async fn delete(pool: &SqlitePool, user_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Update the hosting package assigned to a user.  Pass `None` to remove
/// the package assignment (downgrade / unassign).
pub async fn update_package(
    pool: &SqlitePool,
    user_id: i64,
    package_id: Option<i64>,
) -> Result<(), sqlx::Error> {
    let now = chrono::Utc::now();
    sqlx::query("UPDATE users SET package_id = ?, updated_at = ? WHERE id = ?")
        .bind(package_id)
        .bind(now)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}
