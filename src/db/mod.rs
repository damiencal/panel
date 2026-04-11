pub mod antispam;
pub mod audit;
pub mod backup;
pub mod basic_auth;
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
pub mod tasks;
pub mod team;
pub mod tickets;
pub mod usage;
/// Database access layer using SQLx with type-safe queries.
/// All queries are async and compile-time checked.
pub mod users;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqliteSynchronous};
use std::str::FromStr;
use std::sync::OnceLock;

static DB_POOL: OnceLock<SqlitePool> = OnceLock::new();

/// Extract the file-system path from a `sqlite:` URL, if it refers to a real file.
/// Returns `None` for in-memory databases (`sqlite::memory:`) or unrecognised schemes.
fn sqlite_file_path(url: &str) -> Option<std::path::PathBuf> {
    // sqlite:///abs/path  →  /abs/path
    if let Some(rest) = url.strip_prefix("sqlite:///") {
        return Some(std::path::PathBuf::from(format!("/{rest}")));
    }
    // sqlite:/abs/path  →  /abs/path   (single-slash form used in panel.toml)
    if let Some(rest) = url.strip_prefix("sqlite:") {
        if rest.starts_with('/') {
            return Some(std::path::PathBuf::from(rest));
        }
    }
    None
}

/// Initialize the database pool.
pub async fn init_pool(database_url: &str) -> Result<(), sqlx::Error> {
    // Check that the database directory exists before attempting to connect.
    // SQLite error 14 (CANTOPEN) is cryptic; surface an actionable message instead.
    if let Some(db_path) = sqlite_file_path(database_url) {
        if let Some(parent) = db_path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                return Err(sqlx::Error::Configuration(
                    format!(
                        "Database directory '{}' does not exist.\n\
                         The panel has not been installed yet. \
                         Run the install script (install.sh) to complete setup, \
                         or update [database] url in panel.toml to point to an existing path.",
                        parent.display()
                    )
                    .into(),
                ));
            }
        }
    }

    let options = SqliteConnectOptions::from_str(database_url)?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal);

    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .connect_with(options)
        .await
        .map_err(|e| {
            // Detect SQLITE_CANTOPEN (code 14) and surface an actionable message.
            let is_cantopen = e
                .as_database_error()
                .and_then(|d| d.code())
                .map(|c| c == "14")
                .unwrap_or_else(|| e.to_string().contains("unable to open database"));
            if is_cantopen {
                sqlx::Error::Configuration(
                    format!(
                        "Cannot open database '{database_url}': SQLite error 14 (CANTOPEN).\n\
                         The panel may not be fully installed. \
                         Run install.sh to complete setup, or verify the path and \
                         permissions of [database] url in panel.toml.\n\
                         Original error: {e}"
                    )
                    .into(),
                )
            } else {
                e
            }
        })?;
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
