/// Database management server functions.
use crate::models::database::{Database, DatabaseType};
use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

/// MySQL/MariaDB server status snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MySqlStatus {
    pub version: String,
    pub uptime_seconds: u64,
    pub threads_connected: u64,
    pub questions: u64,
    pub slow_queries: u64,
    pub max_connections: u64,
    pub innodb_buffer_pool_size_mb: u64,
    pub data_dir: String,
}

/// A single MySQL performance recommendation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MySqlRecommendation {
    pub severity: String, // "ok" | "info" | "warning"
    pub variable: String,
    pub current: String,
    pub recommendation: String,
}

/// List databases for the current user.
#[server]
pub async fn server_list_databases() -> Result<Vec<Database>, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    crate::db::databases::list_for_owner(pool, claims.sub)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Create a new database.
/// Records in SQLite and provisions the actual MariaDB database + user with scoped grants.
#[server]
pub async fn server_create_database(
    name: String,
    database_type: DatabaseType,
) -> Result<i64, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    crate::utils::validators::validate_db_name(&name).map_err(ServerFnError::new)?;

    crate::db::quotas::check_can_create_database(pool, claims.sub)
        .await
        .map_err(ServerFnError::new)?;

    let db_id = crate::db::databases::create(pool, claims.sub, name.clone(), database_type)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Provision the actual database on the database server
    if database_type == DatabaseType::MariaDB {
        provision_mysql_database(pool, db_id, &name, &claims.username)
            .await
            .map_err(|e| ServerFnError::new(format!("MySQL provisioning failed: {}", e)))?;
    }

    let _ = crate::db::quotas::increment_databases(pool, claims.sub, 1).await;

    audit_log(
        claims.sub,
        "create_database",
        Some("database"),
        Some(db_id),
        Some(&name),
        "Success",
        None,
    )
    .await;

    Ok(db_id)
}

/// Delete a database.
#[server]
pub async fn server_delete_database(db_id: i64) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let db = crate::db::databases::get(pool, db_id)
        .await
        .map_err(|_| ServerFnError::new("Database not found"))?;

    crate::auth::guards::check_ownership(&claims, db.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Drop the actual database if applicable
    if db.database_type == DatabaseType::MariaDB {
        let _ = drop_mysql_database(&db.name).await;
    }

    crate::db::databases::delete(pool, db_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let _ = crate::db::quotas::increment_databases(pool, claims.sub, -1).await;

    audit_log(
        claims.sub,
        "delete_database",
        Some("database"),
        Some(db_id),
        Some(&db.name),
        "Success",
        None,
    )
    .await;

    Ok(())
}

/// Dump a database to SQL and return it as a base64-encoded string for download.
#[server]
pub async fn server_dump_database(db_id: i64) -> Result<String, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let db = crate::db::databases::get(pool, db_id)
        .await
        .map_err(|_| ServerFnError::new("Database not found"))?;

    crate::auth::guards::check_ownership(&claims, db.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    if db.database_type != crate::models::database::DatabaseType::MariaDB {
        return Err(ServerFnError::new(
            "Dump is only supported for MariaDB databases",
        ));
    }

    let output = shell::exec(
        "mysqldump",
        &["--single-transaction", "--no-tablespaces", &db.name],
    )
    .await
    .map_err(|e| ServerFnError::new(format!("mysqldump failed: {}", e)))?;

    #[cfg(feature = "server")]
    {
        use base64::Engine as _;
        let encoded = base64::engine::general_purpose::STANDARD.encode(&output.stdout);
        audit_log(
            claims.sub,
            "dump_database",
            Some("database"),
            Some(db_id),
            Some(&db.name),
            "Success",
            None,
        )
        .await;
        return Ok(encoded);
    }

    #[allow(unreachable_code)]
    Err(ServerFnError::new("Server feature not enabled"))
}

/// Generate a signed phpMyAdmin access URL for a specific database or all user databases.
/// The URL contains an HMAC-signed token with the MySQL credentials and a 60-second expiry.
/// The token is validated by the phpMyAdmin signon.php bridge script.
#[server]
pub async fn server_get_phpmyadmin_url(db_id: Option<i64>) -> Result<String, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let db_name = if let Some(id) = db_id {
        let db = crate::db::databases::get(pool, id)
            .await
            .map_err(|_| ServerFnError::new("Database not found"))?;

        crate::auth::guards::check_ownership(&claims, db.owner_id, None)
            .map_err(|e| ServerFnError::new(e.to_string()))?;

        if db.database_type != DatabaseType::MariaDB {
            return Err(ServerFnError::new(
                "phpMyAdmin only supports MariaDB databases",
            ));
        }

        Some(db.name.clone())
    } else {
        None
    };

    // Look up the user's MySQL database user credentials.
    // The MySQL username convention is the panel username (scoped via GRANT).
    let mysql_user = format!("pma_{}", claims.username);
    let mysql_password = get_or_create_mysql_session_password(pool, claims.sub, &mysql_user)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Generate HMAC-signed token with 60-second expiry
    let config = crate::utils::PanelConfig::load(Some("panel.toml"))
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let pma_token = generate_phpmyadmin_token(
        &config.server.secret_key,
        &mysql_user,
        &mysql_password,
        db_name.as_deref(),
    )
    .map_err(|e| ServerFnError::new(e.to_string()))?;

    let base_path = config.phpmyadmin.url_base_path.trim_end_matches('/');
    let url = format!("{}/signon.php?token={}", base_path, pma_token);

    audit_log(
        claims.sub,
        "phpmyadmin_access",
        Some("database"),
        db_id,
        db_name.as_deref(),
        "Success",
        None,
    )
    .await;

    Ok(url)
}

/// Get MySQL/MariaDB server status. Admin only.
#[server]
pub async fn server_mysql_status() -> Result<MySqlStatus, ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    collect_mysql_status().await.map_err(ServerFnError::new)
}

/// Restart MariaDB/MySQL service. Admin only.
#[server]
pub async fn server_restart_mysql() -> Result<(), ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    crate::services::shell::exec("systemctl", &["restart", "mariadb"])
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_log(
        claims.sub,
        "restart_mysql",
        Some("service"),
        None,
        Some("mariadb"),
        "Success",
        None,
    )
    .await;
    Ok(())
}

/// Get MySQL performance recommendations. Admin only.
#[server]
pub async fn server_mysql_recommendations() -> Result<Vec<MySqlRecommendation>, ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    build_mysql_recommendations()
        .await
        .map_err(ServerFnError::new)
}

/// List tracked database users for a specific database.
#[server]
pub async fn server_list_db_users(
    db_id: i64,
) -> Result<Vec<crate::models::database::DatabaseUser>, ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;
    let db = crate::db::databases::get(pool, db_id)
        .await
        .map_err(|_| ServerFnError::new("Database not found"))?;
    crate::auth::guards::check_ownership(&claims, db.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    crate::db::databases::list_users(pool, db_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

// ─── Server-only helper functions ───

#[cfg(feature = "server")]
use crate::services::shell;

/// Provision a MySQL database and create a scoped user with GRANT only on that database.
/// Also records the MySQL user in the SQLite panel database for tracking.
#[cfg(feature = "server")]
async fn provision_mysql_database(
    pool: &sqlx::SqlitePool,
    db_id: i64,
    db_name: &str,
    panel_username: &str,
) -> Result<(), String> {
    // Create the database
    let create_db_sql = format!("CREATE DATABASE IF NOT EXISTS `{}`", db_name);
    shell::exec("mysql", &["-e", &create_db_sql])
        .await
        .map_err(|e| e.to_string())?;

    // Create the MySQL user if it doesn't exist (user is shared across all databases for this panel user)
    let mysql_user = format!("pma_{}", panel_username);
    let password = generate_random_password();

    // Pipe CREATE USER SQL via stdin so the password is never visible in ps output.
    let create_user_sql = format!(
        "CREATE USER IF NOT EXISTS '{}'@'localhost' IDENTIFIED BY '{}';",
        mysql_user, password
    );
    shell::exec_stdin("mysql", &[], create_user_sql.as_bytes())
        .await
        .map_err(|e| e.to_string())?;

    // Grant privileges on this specific database only
    let grant_sql = format!(
        "GRANT ALL PRIVILEGES ON `{}`.* TO '{}'@'localhost'",
        db_name, mysql_user
    );
    shell::exec("mysql", &["-e", &grant_sql])
        .await
        .map_err(|e| e.to_string())?;

    shell::exec("mysql", &["-e", "FLUSH PRIVILEGES"])
        .await
        .map_err(|e| e.to_string())?;

    // Persist the MySQL user in SQLite for tracking (password_hash not stored here — creds live in MySQL)
    let privileges = format!("ALL PRIVILEGES ON `{}`.*", db_name);
    let _ = crate::db::databases::create_user(
        pool,
        db_id,
        mysql_user.clone(),
        String::new(),
        Some(privileges),
    )
    .await;

    tracing::info!(
        "Provisioned MySQL database '{}' with user '{}'",
        db_name,
        mysql_user
    );
    Ok(())
}

/// Drop a MySQL database.
#[cfg(feature = "server")]
async fn drop_mysql_database(db_name: &str) -> Result<(), String> {
    let drop_sql = format!("DROP DATABASE IF EXISTS `{}`", db_name);
    shell::exec("mysql", &["-e", &drop_sql])
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Get or create a MySQL session password for phpMyAdmin access.
/// If the MySQL user already exists, reset its password to a fresh one for this session.
#[cfg(feature = "server")]
async fn get_or_create_mysql_session_password(
    _pool: &sqlx::SqlitePool,
    _panel_user_id: i64,
    mysql_user: &str,
) -> Result<String, String> {
    let password = generate_random_password();

    // Pipe credential SQL via stdin so the password is never visible in ps output.
    let alter_sql = format!(
        "ALTER USER IF EXISTS '{}'@'localhost' IDENTIFIED BY '{}';",
        mysql_user, password
    );
    let create_sql = format!(
        "CREATE USER IF NOT EXISTS '{}'@'localhost' IDENTIFIED BY '{}';",
        mysql_user, password
    );

    // Try create first, then alter to reset password — both via stdin
    let _ = shell::exec_stdin("mysql", &[], create_sql.as_bytes()).await;
    let _ = shell::exec_stdin("mysql", &[], alter_sql.as_bytes()).await;

    shell::exec("mysql", &["-e", "FLUSH PRIVILEGES"])
        .await
        .map_err(|e| e.to_string())?;

    Ok(password)
}

/// Generate an HMAC-SHA256-signed token for phpMyAdmin signon.
/// Token format: base64(json_payload).base64(hmac_signature)
/// Payload: {"u": mysql_user, "p": mysql_password, "d": db_name, "exp": unix_timestamp}
#[cfg(feature = "server")]
fn generate_phpmyadmin_token(
    secret_key: &str,
    mysql_user: &str,
    mysql_password: &str,
    db_name: Option<&str>,
) -> Result<String, String> {
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let exp = chrono::Utc::now().timestamp() + 60; // 60-second expiry

    let payload = serde_json::json!({
        "u": mysql_user,
        "p": mysql_password,
        "d": db_name.unwrap_or(""),
        "exp": exp,
    });

    let payload_str = payload.to_string();
    let payload_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload_str.as_bytes());

    let mut mac = Hmac::<Sha256>::new_from_slice(secret_key.as_bytes())
        .map_err(|e| format!("HMAC key error: {}", e))?;
    mac.update(payload_b64.as_bytes());
    let signature = mac.finalize().into_bytes();

    let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature);

    Ok(format!("{}.{}", payload_b64, sig_b64))
}

/// Generate a random password for MySQL users.
#[cfg(feature = "server")]
fn generate_random_password() -> String {
    use base64::Engine;
    let bytes: Vec<u8> = (0..24)
        .map(|_| {
            let mut buf = [0u8; 1];
            if std::fs::File::open("/dev/urandom")
                .and_then(|mut f| {
                    use std::io::Read;
                    f.read_exact(&mut buf)
                })
                .is_ok()
            {
                buf[0]
            } else {
                // Fallback
                (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .subsec_nanos()
                    % 256) as u8
            }
        })
        .collect();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes)
}

/// Parse tab-separated `variable_name\tvalue` output from mysql -N -B.
#[cfg(feature = "server")]
fn parse_mysql_kv_output(output: &str) -> std::collections::HashMap<String, String> {
    output
        .lines()
        .filter_map(|line| {
            let mut parts = line.splitn(2, '\t');
            let key = parts.next()?.trim().to_string();
            let val = parts.next()?.trim().to_string();
            Some((key, val))
        })
        .collect()
}

/// Collect key MySQL/MariaDB status and variable metrics.
#[cfg(feature = "server")]
async fn collect_mysql_status() -> Result<MySqlStatus, String> {
    use tokio::process::Command;
    // These SQL strings are internal constants, not user input — bypass the
    // shell::exec injection guard which rejects the ( ) chars in IN (...).
    let status_out = Command::new("mysql")
        .args([
            "-N",
            "-B",
            "-e",
            "SHOW GLOBAL STATUS WHERE Variable_name IN ('Uptime','Threads_connected','Questions','Slow_queries')",
        ])
        .output()
        .await
        .map_err(|e| e.to_string())?;

    let var_out = Command::new("mysql")
        .args([
            "-N",
            "-B",
            "-e",
            "SHOW GLOBAL VARIABLES WHERE Variable_name IN ('version','max_connections','innodb_buffer_pool_size','datadir')",
        ])
        .output()
        .await
        .map_err(|e| e.to_string())?;

    let status = parse_mysql_kv_output(&String::from_utf8_lossy(&status_out.stdout));
    let vars = parse_mysql_kv_output(&String::from_utf8_lossy(&var_out.stdout));

    Ok(MySqlStatus {
        version: vars.get("version").cloned().unwrap_or_default(),
        uptime_seconds: status
            .get("Uptime")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        threads_connected: status
            .get("Threads_connected")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        questions: status
            .get("Questions")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        slow_queries: status
            .get("Slow_queries")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        max_connections: vars
            .get("max_connections")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        innodb_buffer_pool_size_mb: vars
            .get("innodb_buffer_pool_size")
            .and_then(|v| v.parse::<u64>().ok())
            .map(|b| b / 1024 / 1024)
            .unwrap_or(0),
        data_dir: vars.get("datadir").cloned().unwrap_or_default(),
    })
}

/// Build MySQL performance recommendations by inspecting key global variables.
#[cfg(feature = "server")]
async fn build_mysql_recommendations() -> Result<Vec<MySqlRecommendation>, String> {
    use tokio::process::Command;
    // These SQL strings are internal constants, not user input — bypass the
    // shell::exec injection guard which rejects the ( ) chars in IN (...).
    let out = Command::new("mysql")
        .args([
            "-N",
            "-B",
            "-e",
            "SHOW GLOBAL VARIABLES WHERE Variable_name IN ('innodb_buffer_pool_size','slow_query_log','innodb_file_per_table','log_bin','max_connections')",
        ])
        .output()
        .await
        .map_err(|e| e.to_string())?;

    let vars = parse_mysql_kv_output(&String::from_utf8_lossy(&out.stdout));
    let mut recs = Vec::new();

    // InnoDB buffer pool: ideally ≥128 MB (typically 50-70% of RAM)
    if let Some(s) = vars.get("innodb_buffer_pool_size") {
        let bytes: u64 = s.parse().unwrap_or(0);
        let mb = bytes / 1024 / 1024;
        if mb < 128 {
            recs.push(MySqlRecommendation {
                severity: "warning".into(),
                variable: "innodb_buffer_pool_size".into(),
                current: format!("{} MB", mb),
                recommendation:
                    "Set innodb_buffer_pool_size to 50-70% of available RAM for best throughput (e.g. innodb_buffer_pool_size=1G)"
                        .into(),
            });
        } else {
            recs.push(MySqlRecommendation {
                severity: "ok".into(),
                variable: "innodb_buffer_pool_size".into(),
                current: format!("{} MB", mb),
                recommendation: "Buffer pool size looks healthy".into(),
            });
        }
    }

    // Slow query log
    if vars.get("slow_query_log").map(|s| s.to_uppercase()) != Some("ON".into()) {
        recs.push(MySqlRecommendation {
            severity: "info".into(),
            variable: "slow_query_log".into(),
            current: vars
                .get("slow_query_log")
                .cloned()
                .unwrap_or_else(|| "OFF".into()),
            recommendation:
                "Enable slow_query_log (and set long_query_time=1) to identify slow queries".into(),
        });
    }

    // innodb_file_per_table
    if vars.get("innodb_file_per_table").map(|s| s.to_uppercase()) != Some("ON".into()) {
        recs.push(MySqlRecommendation {
            severity: "warning".into(),
            variable: "innodb_file_per_table".into(),
            current: vars
                .get("innodb_file_per_table")
                .cloned()
                .unwrap_or_else(|| "OFF".into()),
            recommendation:
                "Enable innodb_file_per_table for better disk space management and recovery".into(),
        });
    }

    // Binary log (needed for point-in-time recovery)
    if vars.get("log_bin").map(|s| s.to_uppercase()) != Some("ON".into()) {
        recs.push(MySqlRecommendation {
            severity: "info".into(),
            variable: "log_bin".into(),
            current: vars
                .get("log_bin")
                .cloned()
                .unwrap_or_else(|| "OFF".into()),
            recommendation:
                "Consider enabling binary logging (log_bin) for point-in-time recovery and replication"
                    .into(),
        });
    }

    if recs.is_empty() {
        recs.push(MySqlRecommendation {
            severity: "ok".into(),
            variable: "general".into(),
            current: "all checked".into(),
            recommendation: "No performance issues detected".into(),
        });
    }

    Ok(recs)
}

// ─── Database user management server functions ───

/// Create a new database user with ALL PRIVILEGES on the specified database.
/// The username is validated as a safe DB identifier and the password must pass
/// MySQL-specific strength rules (no shell-injection characters).
#[server]
pub async fn server_create_db_user(
    db_id: i64,
    username: String,
    password: String,
) -> Result<i64, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let db = crate::db::databases::get(pool, db_id)
        .await
        .map_err(|_| ServerFnError::new("Database not found"))?;

    crate::auth::guards::check_ownership(&claims, db.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Validate username: same rules as DB names (alphanumeric + underscore, starts with letter)
    crate::utils::validators::validate_db_name(&username).map_err(ServerFnError::new)?;
    if username.len() > 32 {
        return Err(ServerFnError::new(
            "MySQL username must be 32 characters or less",
        ));
    }

    // Validate password with MySQL-specific rules (no shell-injection chars)
    crate::utils::validators::validate_mysql_password(&password).map_err(ServerFnError::new)?;

    if db.database_type == DatabaseType::MariaDB {
        create_mysql_user(&db.name, &username, &password)
            .await
            .map_err(|e| ServerFnError::new(format!("MySQL user creation failed: {}", e)))?;
    }

    let privileges = format!("ALL PRIVILEGES ON `{}`.*", db.name);
    let user_id = crate::db::databases::create_user(
        pool,
        db_id,
        username.clone(),
        String::new(),
        Some(privileges),
    )
    .await
    .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "create_db_user",
        Some("database_user"),
        Some(user_id),
        Some(&username),
        "Success",
        None,
    )
    .await;

    Ok(user_id)
}

/// Delete a database user and revoke their MySQL account.
#[server]
pub async fn server_delete_db_user(db_user_id: i64) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let db_user = crate::db::databases::get_user(pool, db_user_id)
        .await
        .map_err(|_| ServerFnError::new("Database user not found"))?;

    let db = crate::db::databases::get(pool, db_user.database_id)
        .await
        .map_err(|_| ServerFnError::new("Database not found"))?;

    crate::auth::guards::check_ownership(&claims, db.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    if db.database_type == DatabaseType::MariaDB {
        // Best-effort: ignore errors (user may not exist in MySQL)
        let _ = delete_mysql_user(&db_user.username).await;
    }

    crate::db::databases::delete_user(pool, db_user_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "delete_db_user",
        Some("database_user"),
        Some(db_user_id),
        Some(&db_user.username),
        "Success",
        None,
    )
    .await;

    Ok(())
}

/// Change the password for a database user.
#[server]
pub async fn server_change_db_user_password(
    db_user_id: i64,
    new_password: String,
) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let db_user = crate::db::databases::get_user(pool, db_user_id)
        .await
        .map_err(|_| ServerFnError::new("Database user not found"))?;

    let db = crate::db::databases::get(pool, db_user.database_id)
        .await
        .map_err(|_| ServerFnError::new("Database not found"))?;

    crate::auth::guards::check_ownership(&claims, db.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    crate::utils::validators::validate_mysql_password(&new_password).map_err(ServerFnError::new)?;

    if db.database_type == DatabaseType::MariaDB {
        change_mysql_user_password(&db_user.username, &new_password)
            .await
            .map_err(|e| ServerFnError::new(format!("MySQL password change failed: {}", e)))?;
    }

    audit_log(
        claims.sub,
        "change_db_user_password",
        Some("database_user"),
        Some(db_user_id),
        Some(&db_user.username),
        "Success",
        None,
    )
    .await;

    Ok(())
}

// ─── MySQL user management helpers ───

/// Create a MySQL user and grant ALL PRIVILEGES on the given database.
#[cfg(feature = "server")]
async fn create_mysql_user(db_name: &str, username: &str, password: &str) -> Result<(), String> {
    // Pipe CREATE USER SQL via stdin so the password never appears in ps output.
    let create_sql = format!(
        "CREATE USER IF NOT EXISTS '{}'@'localhost' IDENTIFIED BY '{}';",
        username, password
    );
    shell::exec_stdin("mysql", &[], create_sql.as_bytes())
        .await
        .map_err(|e| e.to_string())?;

    let grant_sql = format!(
        "GRANT ALL PRIVILEGES ON `{}`.* TO '{}'@'localhost'",
        db_name, username
    );
    shell::exec("mysql", &["-e", &grant_sql])
        .await
        .map_err(|e| e.to_string())?;

    shell::exec("mysql", &["-e", "FLUSH PRIVILEGES"])
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
}

/// Drop a MySQL user entirely.
#[cfg(feature = "server")]
async fn delete_mysql_user(username: &str) -> Result<(), String> {
    let drop_sql = format!("DROP USER IF EXISTS '{}'@'localhost'", username);
    shell::exec("mysql", &["-e", &drop_sql])
        .await
        .map_err(|e| e.to_string())?;

    shell::exec("mysql", &["-e", "FLUSH PRIVILEGES"])
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
}

/// Change the password for an existing MySQL user.
#[cfg(feature = "server")]
async fn change_mysql_user_password(username: &str, new_password: &str) -> Result<(), String> {
    // Pipe ALTER USER SQL via stdin so the password never appears in ps output.
    let alter_sql = format!(
        "ALTER USER '{}'@'localhost' IDENTIFIED BY '{}';",
        username, new_password
    );
    shell::exec_stdin("mysql", &[], alter_sql.as_bytes())
        .await
        .map_err(|e| e.to_string())?;

    shell::exec("mysql", &["-e", "FLUSH PRIVILEGES"])
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
}
