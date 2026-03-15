/// GoAccess real-time web log analyzer.
///
/// GoAccess reads the Combined Log Format access log produced by OpenLiteSpeed
/// and outputs a self-contained HTML dashboard.
use super::{shell, ServiceError};
use std::path::Path;
use tokio::fs;
use tracing::info;

/// Return true if the `goaccess` binary exists on this system.
pub async fn is_installed() -> bool {
    shell::command_exists("goaccess").await
}

/// Install GoAccess via apt-get.
pub async fn install() -> Result<(), ServiceError> {
    info!("Installing GoAccess...");
    shell::exec("apt-get", &["install", "-y", "goaccess"]).await?;
    info!("GoAccess installed");
    Ok(())
}

/// Generate a GoAccess HTML report for a domain.
///
/// * `access_log`  – path to OLS combined-format access log
/// * `output_dir`  – directory where `report.html` is written
/// * `domain`      – used for logging only
pub async fn generate(
    access_log: &str,
    output_dir: &str,
    domain: &str,
) -> Result<(), ServiceError> {
    if !shell::command_exists("goaccess").await {
        return Err(ServiceError::NotInstalled);
    }

    crate::utils::validators::validate_domain(domain)
        .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;
    crate::utils::validators::validate_safe_path(access_log, "/usr/local/lsws/logs/")
        .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;
    crate::utils::validators::validate_safe_path(output_dir, "/var/www/")
        .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;

    if !Path::new(access_log).exists() {
        return Err(ServiceError::IoError(format!(
            "Access log not found: {access_log}"
        )));
    }

    fs::create_dir_all(output_dir)
        .await
        .map_err(|e| ServiceError::IoError(e.to_string()))?;

    let output_file = format!("{}/report.html", output_dir);

    info!("Running GoAccess for {} → {}", domain, output_file);

    shell::exec(
        "goaccess",
        &[
            access_log,
            "--log-format=COMBINED",
            "--output",
            &output_file,
            "--no-global-config",
        ],
    )
    .await?;

    info!("GoAccess report generated for {}", domain);
    Ok(())
}
