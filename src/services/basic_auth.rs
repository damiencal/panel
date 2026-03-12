/// HTTP Basic Authentication management service.
/// Manages per-site htpasswd files using APR1-MD5 hashing (Apache-compatible).
/// OpenLiteSpeed supports the Apache htpasswd format natively.
use super::{shell, ServiceError};
use crate::utils::validators;
use std::path::Path;
use tokio::fs;
use tracing::info;

/// Directory where per-site htpasswd files are stored.
const HTPASSWD_DIR: &str = "/etc/panel/htpasswd";

/// Directory where custom SSL certificate files are stored
/// (for certificates uploaded by users rather than issued via Certbot).
const CUSTOM_CERT_DIR: &str = "/etc/ssl/panel";

/// Return the absolute path to the htpasswd file for a domain.
pub fn htpasswd_path(domain: &str) -> String {
    format!("{}/{}.htpasswd", HTPASSWD_DIR, domain)
}

/// Return the paths to the custom cert and key files for a domain.
pub fn custom_cert_paths(domain: &str) -> (String, String) {
    let cert_path = format!("{}/{}/fullchain.pem", CUSTOM_CERT_DIR, domain);
    let key_path = format!("{}/{}/privkey.pem", CUSTOM_CERT_DIR, domain);
    (cert_path, key_path)
}

/// Hash a password using APR1-MD5 via `openssl passwd -apr1`.
/// The password is piped via stdin so it never appears in the process argument list.
pub async fn hash_password(password: &str) -> Result<String, ServiceError> {
    // Defense-in-depth: reject passwords containing null bytes or newlines that
    // could corrupt the htpasswd file or confuse the openssl command.
    if password.contains('\0') || password.contains('\n') || password.contains('\r') {
        return Err(ServiceError::CommandFailed(
            "Password contains invalid characters".to_string(),
        ));
    }
    if password.is_empty() {
        return Err(ServiceError::CommandFailed(
            "Password must not be empty".to_string(),
        ));
    }

    let output = shell::exec_stdin(
        "openssl",
        &["passwd", "-apr1", "-stdin"],
        password.as_bytes(),
    )
    .await?;

    let hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if hash.is_empty() {
        return Err(ServiceError::CommandFailed(
            "openssl passwd produced empty output".to_string(),
        ));
    }
    Ok(hash)
}

/// Write (or overwrite) the htpasswd file for a domain with the provided users.
/// `users` is a slice of `(username, password_hash)` pairs already in htpasswd
/// format (produced by `hash_password`).
pub async fn write_htpasswd(domain: &str, users: &[(String, String)]) -> Result<(), ServiceError> {
    // Defense-in-depth: validate domain before constructing file path.
    validators::validate_domain(domain).map_err(|e| ServiceError::CommandFailed(e.to_string()))?;

    fs::create_dir_all(HTPASSWD_DIR)
        .await
        .map_err(|e| ServiceError::IoError(e.to_string()))?;

    let path = htpasswd_path(domain);
    // Validate that the resulting path is inside the expected directory to prevent
    // path traversal (the domain validator already blocks /, .., but be explicit).
    if !path.starts_with(HTPASSWD_DIR) {
        return Err(ServiceError::CommandFailed(
            "htpasswd path outside expected directory".to_string(),
        ));
    }

    let mut content = String::new();
    for (username, hash) in users {
        // Validate each username: must not contain ':' or newlines (would corrupt the file).
        if username.contains(':') || username.contains('\n') || username.contains('\r') {
            return Err(ServiceError::CommandFailed(format!(
                "Username '{}' contains invalid characters",
                username
            )));
        }
        validators::validate_username(username)
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;
        content.push_str(&format!("{}:{}\n", username, hash));
    }

    fs::write(&path, &content)
        .await
        .map_err(|e| ServiceError::IoError(e.to_string()))?;

    info!("Wrote htpasswd for {}: {} users", domain, users.len());
    Ok(())
}

/// Remove the htpasswd file for a domain (called when Basic Auth is disabled
/// or the site is deleted).
pub async fn remove_htpasswd(domain: &str) -> Result<(), ServiceError> {
    validators::validate_domain(domain).map_err(|e| ServiceError::CommandFailed(e.to_string()))?;

    let path = htpasswd_path(domain);
    if Path::new(&path).exists() {
        fs::remove_file(&path)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;
        info!("Removed htpasswd for {}", domain);
    }
    Ok(())
}

/// Write custom SSL certificate PEM files for a domain to disk.
/// Returns `(cert_path, key_path)` of the written files.
///
/// # Security
/// - PEM content is validated for the expected PEM block headers.
/// - Paths are constructed from the validated domain and a fixed base directory.
/// - File permissions are set to 600 so only the panel process can read the key.
pub async fn write_custom_cert(
    domain: &str,
    cert_pem: &str,
    key_pem: &str,
) -> Result<(String, String), ServiceError> {
    // Defense-in-depth: validate domain.
    validators::validate_domain(domain).map_err(|e| ServiceError::CommandFailed(e.to_string()))?;

    // Require PEM headers to catch accidental DER-encoded uploads.
    if !cert_pem.contains("-----BEGIN CERTIFICATE-----") {
        return Err(ServiceError::CommandFailed(
            "Certificate does not contain a PEM CERTIFICATE block".to_string(),
        ));
    }
    if !key_pem.contains("-----BEGIN") {
        return Err(ServiceError::CommandFailed(
            "Private key does not appear to be in PEM format".to_string(),
        ));
    }
    // Block null bytes and other control chars that could corrupt the PEM files.
    if cert_pem.contains('\0') || key_pem.contains('\0') {
        return Err(ServiceError::CommandFailed(
            "PEM content contains null bytes".to_string(),
        ));
    }

    let cert_dir = format!("{}/{}", CUSTOM_CERT_DIR, domain);
    let (cert_path, key_path) = custom_cert_paths(domain);

    // Validate that derived paths stay inside the expected directory.
    if !cert_path.starts_with(CUSTOM_CERT_DIR) || !key_path.starts_with(CUSTOM_CERT_DIR) {
        return Err(ServiceError::CommandFailed(
            "Cert path is outside expected directory".to_string(),
        ));
    }

    fs::create_dir_all(&cert_dir)
        .await
        .map_err(|e| ServiceError::IoError(e.to_string()))?;

    fs::write(&cert_path, cert_pem)
        .await
        .map_err(|e| ServiceError::IoError(e.to_string()))?;

    // Write the private key with restrictive permissions (0600).
    #[cfg(unix)]
    {
        let mut opts = tokio::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true).mode(0o600);
        use tokio::io::AsyncWriteExt;
        let mut f = opts
            .open(&key_path)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;
        f.write_all(key_pem.as_bytes())
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;
    }
    #[cfg(not(unix))]
    fs::write(&key_path, key_pem)
        .await
        .map_err(|e| ServiceError::IoError(e.to_string()))?;

    info!("Wrote custom SSL cert for {}", domain);
    Ok((cert_path, key_path))
}

/// Verify that a certificate file matches the given private key using openssl.
/// Returns Ok(()) if they match, Err if they don't.
pub async fn verify_cert_key_pair(cert_path: &str, key_path: &str) -> Result<(), ServiceError> {
    // Get the public key modulus from the cert.
    let cert_mod =
        shell::exec("openssl", &["x509", "-in", cert_path, "-noout", "-modulus"]).await?;

    // Get the public key modulus from the private key.
    let key_mod = shell::exec("openssl", &["rsa", "-in", key_path, "-noout", "-modulus"]).await?;

    if cert_mod.stdout != key_mod.stdout {
        return Err(ServiceError::CommandFailed(
            "Certificate and private key do not match".to_string(),
        ));
    }
    Ok(())
}
