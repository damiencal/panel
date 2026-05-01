/// PHP-FPM pool management for per-customer isolation.
use crate::services::shell;
use crate::utils::validators::validate_username;
use std::path::Path;
use tracing::info;

pub const DEFAULT_PHP_VERSION: &str = "8.3";

const SUPPORTED_PHP_VERSIONS: &[&str] = &["8.1", "8.2", "8.3", "8.4"];

const DISABLED_FUNCTIONS: &str =
    "exec,passthru,shell_exec,system,proc_open,popen,\
     curl_exec,curl_multi_exec,parse_ini_file,show_source";

/// Return the Unix socket path for a given username.
pub fn socket_path(username: &str) -> String {
    format!("/run/php/fpm-{}.sock", username)
}

/// Create a PHP-FPM pool config for username.
pub async fn create_pool(username: &str, php_version: &str) -> Result<(), crate::services::ServiceError> {
    validate_username(username)
        .map_err(|e| crate::services::ServiceError::CommandFailed(e.to_string()))?;
    validate_php_version(php_version)?;
    let config = generate_pool_config(username, false);
    write_pool_file(username, php_version, &config).await?;
    info!("Created PHP-FPM pool for '{}'", username);
    Ok(())
}

/// Delete the PHP-FPM pool config (idempotent).
pub async fn delete_pool(username: &str, php_version: &str) -> Result<(), crate::services::ServiceError> {
    validate_username(username)
        .map_err(|e| crate::services::ServiceError::CommandFailed(e.to_string()))?;
    validate_php_version(php_version)?;
    let path = pool_conf_path(username, php_version);
    if Path::new(&path).exists() {
        shell::exec("rm", &["-f", &path]).await?;
        info!("Deleted PHP-FPM pool '{}'", path);
    }
    Ok(())
}

/// Suspend: set pm=static, pm.max_children=0.
pub async fn suspend_pool(username: &str, php_version: &str) -> Result<(), crate::services::ServiceError> {
    validate_username(username)
        .map_err(|e| crate::services::ServiceError::CommandFailed(e.to_string()))?;
    validate_php_version(php_version)?;
    let config = generate_pool_config(username, true);
    write_pool_file(username, php_version, &config).await?;
    Ok(())
}

/// Unsuspend: restore pm=ondemand.
pub async fn unsuspend_pool(username: &str, php_version: &str) -> Result<(), crate::services::ServiceError> {
    validate_username(username)
        .map_err(|e| crate::services::ServiceError::CommandFailed(e.to_string()))?;
    validate_php_version(php_version)?;
    let config = generate_pool_config(username, false);
    write_pool_file(username, php_version, &config).await?;
    Ok(())
}

/// Reload PHP-FPM for the given version.
pub async fn reload(php_version: &str) -> Result<(), crate::services::ServiceError> {
    validate_php_version(php_version)?;
    let service = format!("php{}-fpm", php_version);
    shell::exec("systemctl", &["reload", &service]).await?;
    Ok(())
}

fn pool_conf_path(username: &str, php_version: &str) -> String {
    format!("/etc/php/{}/fpm/pool.d/{}.conf", php_version, username)
}

async fn write_pool_file(username: &str, php_version: &str, content: &str) -> Result<(), crate::services::ServiceError> {
    let final_path = pool_conf_path(username, php_version);
    let tmp_path   = format!("{}.tmp", final_path);
    tokio::fs::write(&tmp_path, content).await.map_err(|e| {
        crate::services::ServiceError::CommandFailed(format!("PHP-FPM tmp write failed: {e}"))
    })?;
    tokio::fs::rename(&tmp_path, &final_path).await.map_err(|e| {
        crate::services::ServiceError::CommandFailed(format!("PHP-FPM rename failed: {e}"))
    })?;
    Ok(())
}

fn generate_pool_config(username: &str, suspended: bool) -> String {
    let socket   = socket_path(username);
    let home     = format!("/home/{}", username);
    let open_basedir = format!("{}/:/tmp/", home);
    let logs_dir = format!("{}/logs/php-error.log", home);
    let tmp_dir  = format!("{}/tmp", home);
    let pm_section = if suspended {
        "pm = static\npm.max_children = 0\n".to_string()
    } else {
        "pm = ondemand\npm.max_children = 5\npm.process_idle_timeout = 10s\n".to_string()
    };
    format!(
        "[{username}]\nuser  = {username}\ngroup = {username}\nlisten = {socket}\n\
         listen.owner = www-data\nlisten.group = www-data\nlisten.mode  = 0660\n\
         \n{pm_section}\n\
         php_admin_value[open_basedir]       = {open_basedir}\n\
         php_admin_value[disable_functions]  = {disabled}\n\
         php_admin_value[error_log]          = {logs_dir}\n\
         php_admin_value[sys_temp_dir]       = {tmp_dir}\n\
         php_admin_value[upload_tmp_dir]     = {tmp_dir}\n\
         php_flag[display_errors]            = off\n",
        username = username, socket = socket, pm_section = pm_section,
        open_basedir = open_basedir, disabled = DISABLED_FUNCTIONS,
        logs_dir = logs_dir, tmp_dir = tmp_dir,
    )
}

fn validate_php_version(version: &str) -> Result<(), crate::services::ServiceError> {
    if SUPPORTED_PHP_VERSIONS.contains(&version) {
        Ok(())
    } else {
        Err(crate::services::ServiceError::CommandFailed(format!(
            "Unsupported PHP version '{}'; allowed: {:?}", version, SUPPORTED_PHP_VERSIONS
        )))
    }
}
