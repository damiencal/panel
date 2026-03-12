pub mod antispam;
pub mod audit;
pub mod backup;
pub mod branding;
pub mod cron;
pub mod databases;
pub mod dns;
pub mod email;
pub mod ftp;
pub mod git;
pub mod packages;
pub mod quotas;
pub mod sites;
pub mod stats;
pub mod tickets;
pub mod usage;
/// Database access layer using SQLx with type-safe queries.
/// All queries are async and compile-time checked.
pub mod users;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqliteSynchronous};
use std::str::FromStr;
use std::sync::OnceLock;

static DB_POOL: OnceLock<SqlitePool> = OnceLock::new();

/// Initialize the database pool.
pub async fn init_pool(database_url: &str) -> Result<(), sqlx::Error> {
    let options = SqliteConnectOptions::from_str(database_url)?
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal);

    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .connect_with(options)
        .await?;
    // Run migrations
    sqlx::migrate!("./migrations").run(&pool).await?;

    // Seed default admin if no users exist
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(&pool)
        .await?;
    if count.0 == 0 {
        use argon2::{
            password_hash::{rand_core::OsRng, SaltString},
            Argon2, PasswordHasher,
        };
        let salt = SaltString::generate(&mut OsRng);

        let admin_password = std::env::var("PANEL_ADMIN_PASSWORD").unwrap_or_else(|_| {
            let random_pw = uuid::Uuid::new_v4().to_string();
            println!("#########################################################");
            println!("GENERATED DEFAULT ADMIN PASSWORD: {}", random_pw);
            println!("#########################################################");
            random_pw
        });

        let hash = Argon2::default()
            .hash_password(admin_password.as_bytes(), &salt)
            .expect("Failed to hash default admin password")
            .to_string();
        sqlx::query(
            "INSERT INTO users (username, email, password_hash, role, status, created_at, updated_at)
             VALUES ('admin', 'admin@localhost', ?, 'Admin', 'Active', datetime('now'), datetime('now'))"
        )
        .bind(&hash)
        .execute(&pool)
        .await?;
        tracing::info!(
            "Created default admin user (username: admin, using provided or generated password)"
        );
    }

    let _ = DB_POOL.set(pool);
    Ok(())
}

/// Get the database pool.
pub fn pool() -> Result<&'static SqlitePool, &'static str> {
    DB_POOL.get().ok_or("Database pool not initialized")
}

/// Get the database pool as a cloned value (for passing to spawned tasks).
pub fn get_pool_ref() -> &'static SqlitePool {
    DB_POOL.get().expect("Database pool not initialized")
}
