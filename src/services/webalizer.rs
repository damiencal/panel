/// Webalizer web-log statistics generator.
///
/// Webalizer reads the Combined Log Format access log produced by OpenLiteSpeed
/// and outputs a static HTML report directory.
use super::{shell, ServiceError};
use std::path::Path;
use tokio::fs;
use tracing::info;

const WEBALIZER_BIN: &str = "/usr/bin/webalizer";

/// Return true if the `webalizer` binary exists on this system.
pub async fn is_installed() -> bool {
    shell::command_exists("webalizer").await
}

/// Install Webalizer via apt-get.
pub async fn install() -> Result<(), ServiceError> {
    info!("Installing Webalizer...");
    shell::exec("apt-get", &["install", "-y", "webalizer"]).await?;
    info!("Webalizer installed");
    Ok(())
}

/// Generate Webalizer statistics for a domain.
///
/// * `access_log`  – path to OLS combined-format access log
/// * `output_dir`  – directory where the HTML report is written
/// * `domain`      – hostname used in the report title
pub async fn generate(
    access_log: &str,
    output_dir: &str,
    domain: &str,
) -> Result<(), ServiceError> {
    if !Path::new(WEBALIZER_BIN).exists() {
        return Err(ServiceError::NotInstalled);
    }

    if !Path::new(access_log).exists() {
        return Err(ServiceError::IoError(format!(
            "Access log not found: {access_log}"
        )));
    }

    // Ensure output directory exists
    fs::create_dir_all(output_dir)
        .await
        .map_err(|e| ServiceError::IoError(e.to_string()))?;

    info!("Running Webalizer for {} → {}", domain, output_dir);

    shell::exec(WEBALIZER_BIN, &["-n", domain, "-o", output_dir, access_log]).await?;

    info!("Webalizer report generated for {}", domain);
    Ok(())
}
