/// MariaDB database server management.
/// Handles installation, lifecycle, user/database provisioning, and secure defaults.
use super::{shell, ManagedService, ServiceError};
use crate::models::service::{ServiceStatus, ServiceType};
use async_trait::async_trait;
use tracing::info;

const MARIADB_SERVICE: &str = "mariadb";

/// MariaDB service manager.
pub struct MariaDbService;

#[async_trait]
impl ManagedService for MariaDbService {
    fn service_type(&self) -> ServiceType {
        ServiceType::MariaDB
    }

    async fn install(&self) -> Result<(), ServiceError> {
        info!("Installing MariaDB...");

        shell::exec(
            "apt-get",
            &["install", "-y", "mariadb-server", "mariadb-client"],
        )
        .await?;

        shell::exec("systemctl", &["enable", MARIADB_SERVICE]).await?;
        shell::exec("systemctl", &["start", MARIADB_SERVICE]).await?;

        info!("MariaDB installed successfully");
        Ok(())
    }

    async fn start(&self) -> Result<(), ServiceError> {
        info!("Starting MariaDB...");
        shell::exec("systemctl", &["start", MARIADB_SERVICE]).await?;
        Ok(())
    }

    async fn stop(&self) -> Result<(), ServiceError> {
        info!("Stopping MariaDB...");
        shell::exec("systemctl", &["stop", MARIADB_SERVICE]).await?;
        Ok(())
    }

    async fn restart(&self) -> Result<(), ServiceError> {
        info!("Restarting MariaDB...");
        shell::exec("systemctl", &["restart", MARIADB_SERVICE]).await?;
        Ok(())
    }

    async fn status(&self) -> Result<ServiceStatus, ServiceError> {
        match shell::exec("systemctl", &["is-active", MARIADB_SERVICE]).await {
            Ok(output) => {
                let status_str = String::from_utf8_lossy(&output.stdout);
                if status_str.trim() == "active" {
                    Ok(ServiceStatus::Running)
                } else {
                    Ok(ServiceStatus::Stopped)
                }
            }
            Err(_) => Ok(ServiceStatus::Unknown),
        }
    }

    async fn is_installed(&self) -> Result<bool, ServiceError> {
        match shell::exec("which", &["mariadb"]).await {
            Ok(output) => Ok(output.status.success()),
            Err(_) => Ok(false),
        }
    }

    async fn version(&self) -> Result<String, ServiceError> {
        let output = shell::exec("mariadb", &["--version"]).await?;
        let raw = String::from_utf8_lossy(&output.stdout);
        // Extract version number from "mariadb Ver X.X Distrib X.X.X-MariaDB, ..."
        let version = raw
            .split_whitespace()
            .skip_while(|s| !s.eq_ignore_ascii_case("Distrib"))
            .nth(1)
            .map(|v| v.trim_end_matches(',').to_string())
            .unwrap_or_else(|| raw.trim().to_string());
        Ok(version)
    }
}

impl MariaDbService {
    /// Create a MySQL database.
    pub async fn create_database(&self, db_name: &str) -> Result<(), ServiceError> {
        // Defense-in-depth: validate at service layer
        crate::utils::validators::validate_db_name(db_name)
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;

        let sql = format!("CREATE DATABASE IF NOT EXISTS `{}`;
", db_name);
        // Pipe SQL via stdin so the statement is never visible in `ps aux`
        shell::exec_stdin("mysql", &[], sql.as_bytes()).await?;
        info!("Database '{}' created", db_name);
        Ok(())
    }

    /// Drop a MySQL database.
    pub async fn drop_database(&self, db_name: &str) -> Result<(), ServiceError> {
        crate::utils::validators::validate_db_name(db_name)
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;

        let sql = format!("DROP DATABASE IF EXISTS `{}`;
", db_name);
        // Pipe SQL via stdin so the statement is never visible in `ps aux`
        shell::exec_stdin("mysql", &[], sql.as_bytes()).await?;
        info!("Database '{}' dropped", db_name);
        Ok(())
    }

    /// Create a MySQL user and grant privileges on a specific database.
    /// Uses stdin piping to avoid exposing passwords in process listings.
    pub async fn create_user(
        &self,
        username: &str,
        password: &str,
        db_name: &str,
    ) -> Result<(), ServiceError> {
        // Defense-in-depth: validate all inputs at service layer
        crate::utils::validators::validate_username(username)
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;
        crate::utils::validators::validate_mysql_password(password)
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;
        crate::utils::validators::validate_db_name(db_name)
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;

        // Pipe SQL via stdin so the password is never visible in `ps aux`
        let sql = format!(
            "CREATE USER IF NOT EXISTS '{}'@'localhost' IDENTIFIED BY '{}';\n\
             GRANT ALL PRIVILEGES ON `{}`.* TO '{}'@'localhost';\n\
             FLUSH PRIVILEGES;\n",
            username, password, db_name, username
        );
        shell::exec_stdin("mysql", &[], sql.as_bytes()).await?;

        info!("User '{}' created with grants on '{}'", username, db_name);
        Ok(())
    }

    /// Drop a MySQL user.
    pub async fn drop_user(&self, username: &str) -> Result<(), ServiceError> {
        crate::utils::validators::validate_username(username)
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;

        let sql = format!("DROP USER IF EXISTS '{}'@'localhost';
", username);
        // Pipe SQL via stdin so the statement is never visible in `ps aux`
        shell::exec_stdin("mysql", &[], sql.as_bytes()).await?;
        info!("User '{}' dropped", username);
        Ok(())
    }

    /// Revoke all privileges and drop a user's grants on a specific database.
    pub async fn revoke_grants(&self, username: &str, db_name: &str) -> Result<(), ServiceError> {
        crate::utils::validators::validate_username(username)
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;
        crate::utils::validators::validate_db_name(db_name)
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;

        let sql = format!(
            "REVOKE ALL PRIVILEGES ON `{}`.* FROM '{}'@'localhost';\nFLUSH PRIVILEGES;\n",
            db_name, username
        );
        // Pipe SQL via stdin; ignore error if grants didn't exist
        let _ = shell::exec_stdin("mysql", &[], sql.as_bytes()).await;
        Ok(())
    }

    /// Run mysql_secure_installation equivalent hardening.
    pub async fn secure_installation(&self) -> Result<(), ServiceError> {
        info!("Securing MariaDB installation...");

        // Remove anonymous users
        let _ = shell::exec("mysql", &["-e", "DELETE FROM mysql.user WHERE User=''"]).await;

        // Remove remote root login
        let _ = shell::exec(
            "mysql",
            &[
                "-e",
                "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1')",
            ],
        )
        .await;

        // Remove test database
        let _ = shell::exec("mysql", &["-e", "DROP DATABASE IF EXISTS test"]).await;
        let _ = shell::exec(
            "mysql",
            &[
                "-e",
                "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%'",
            ],
        )
        .await;

        shell::exec("mysql", &["-e", "FLUSH PRIVILEGES"]).await?;

        info!("MariaDB secured");
        Ok(())
    }
}
