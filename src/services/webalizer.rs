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

/// Minimal HTML page shown when a site has no access log yet.
fn no_data_html(domain: &str) -> String {
    format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Webalizer – {domain}</title>\
         <style>body{{font-family:sans-serif;display:flex;align-items:center;justify-content:center;\
         height:100vh;margin:0;background:#f8f9fa;}}div{{text-align:center;color:#6c757d;}}</style>\
         </head><body><div><h2>No traffic data yet</h2>\
         <p>The access log for <strong>{domain}</strong> is empty.<br>\
         Statistics will appear here after the site has received its first visitors.</p>\
         </div></body></html>"
    )
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

    crate::utils::validators::validate_domain(domain)
        .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;
    crate::utils::validators::validate_safe_path(access_log, "/usr/local/lsws/logs/")
        .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;
    crate::utils::validators::validate_safe_path(output_dir, "/var/www/")
        .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;

    // Ensure output directory exists
    fs::create_dir_all(output_dir)
        .await
        .map_err(|e| ServiceError::IoError(e.to_string()))?;

    // If no log exists yet, write a placeholder report instead of failing.
    if !Path::new(access_log).exists() {
        let placeholder = no_data_html(domain);
        let output_file = format!("{}/index.html", output_dir);
        fs::write(&output_file, placeholder.as_bytes())
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;
        info!(
            "Webalizer: no access log yet for {} — placeholder report written",
            domain
        );
        return Ok(());
    }

    info!("Running Webalizer for {} → {}", domain, output_dir);

    shell::exec(WEBALIZER_BIN, &["-n", domain, "-o", output_dir, access_log]).await?;

    info!("Webalizer report generated for {}", domain);
    Ok(())
}
