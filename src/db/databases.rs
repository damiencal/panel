/// Database/database-user operations.
use crate::models::database::{Database, DatabaseStatus, DatabaseType, DatabaseUser};
use chrono::Utc;
use sqlx::SqlitePool;

/// Get a database by ID.
pub async fn get(pool: &SqlitePool, db_id: i64) -> Result<Database, sqlx::Error> {
    sqlx::query_as::<_, Database>("SELECT * FROM databases WHERE id = ?")
        .bind(db_id)
        .fetch_one(pool)
        .await
}

/// List databases for an owner.
pub async fn list_for_owner(
    pool: &SqlitePool,
    owner_id: i64,
) -> Result<Vec<Database>, sqlx::Error> {
    sqlx::query_as::<_, Database>("SELECT * FROM databases WHERE owner_id = ? ORDER BY name")
        .bind(owner_id)
        .fetch_all(pool)
        .await
}

/// Create a new database.
pub async fn create(
    pool: &SqlitePool,
    owner_id: i64,
    name: String,
    db_type: DatabaseType,
) -> Result<i64, sqlx::Error> {
    let now = Utc::now();
    let result = sqlx::query(
        "INSERT INTO databases (owner_id, name, database_type, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(owner_id)
    .bind(name)
    .bind(db_type)
    .bind(DatabaseStatus::Active)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

/// Delete a database.
pub async fn delete(pool: &SqlitePool, db_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM databases WHERE id = ?")
        .bind(db_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// List all databases across all owners (admin use only).
pub async fn list_all(pool: &SqlitePool) -> Result<Vec<Database>, sqlx::Error> {
    sqlx::query_as::<_, Database>("SELECT * FROM databases ORDER BY owner_id, name")
        .fetch_all(pool)
        .await
}

// Database user operations

/// Get a database user by ID.
pub async fn get_user(pool: &SqlitePool, user_id: i64) -> Result<DatabaseUser, sqlx::Error> {
    sqlx::query_as::<_, DatabaseUser>("SELECT * FROM database_users WHERE id = ?")
        .bind(user_id)
        .fetch_one(pool)
        .await
}

/// List users for a database.
pub async fn list_users(pool: &SqlitePool, db_id: i64) -> Result<Vec<DatabaseUser>, sqlx::Error> {
    sqlx::query_as::<_, DatabaseUser>(
        "SELECT * FROM database_users WHERE database_id = ? ORDER BY username",
    )
    .bind(db_id)
    .fetch_all(pool)
    .await
}

/// Create a database user.
pub async fn create_user(
    pool: &SqlitePool,
    db_id: i64,
    username: String,
    password_hash: String,
    privileges: Option<String>,
) -> Result<i64, sqlx::Error> {
    let result = sqlx::query(
        "INSERT OR IGNORE INTO database_users (database_id, username, password_hash, privileges, created_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(db_id)
    .bind(username)
    .bind(password_hash)
    .bind(privileges)
    .bind(Utc::now())
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

/// Delete a database user.
pub async fn delete_user(pool: &SqlitePool, user_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM database_users WHERE id = ?")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}
