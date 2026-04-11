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

/// Minimal HTML page shown when a site has no access log yet.
fn no_data_html(domain: &str) -> String {
    format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>GoAccess – {domain}</title>\
         <style>body{{font-family:sans-serif;display:flex;align-items:center;justify-content:center;\
         height:100vh;margin:0;background:#f8f9fa;}}div{{text-align:center;color:#6c757d;}}</style>\
         </head><body><div><h2>No traffic data yet</h2>\
         <p>The access log for <strong>{domain}</strong> is empty.<br>\
         Statistics will appear here after the site has received its first visitors.</p>\
         </div></body></html>"
    )
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

    fs::create_dir_all(output_dir)
        .await
        .map_err(|e| ServiceError::IoError(e.to_string()))?;

    let output_file = format!("{}/report.html", output_dir);

    // If no log exists yet (site has received no traffic), write a placeholder
    // report so the "Run" succeeds and the UI shows a useful message rather
    // than a hard failure.
    if !Path::new(access_log).exists() {
        let placeholder = no_data_html(domain);
        fs::write(&output_file, placeholder.as_bytes())
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;
        info!(
            "GoAccess: no access log yet for {} — placeholder report written",
            domain
        );
        return Ok(());
    }

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
