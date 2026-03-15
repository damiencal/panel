/// TOTP (Time-based One-Time Password) / 2FA implementation.
use crate::models::auth::AuthError;
use totp_rs::{Algorithm, Secret, TOTP};

/// Generate a new TOTP secret for a user.
pub fn generate_totp_secret(username: &str, issuer: &str) -> Result<(String, String), AuthError> {
    let secret = Secret::generate_secret();
    // Use Base32-encoded form so Secret::Encoded() in verify_totp works correctly
    let secret_string = secret.to_encoded().to_string();

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret.to_bytes().map_err(|_| AuthError::InvalidTotpCode)?,
        Some(issuer.to_string()),
        username.to_string(),
    )
    .map_err(|_| AuthError::InvalidTotpCode)?;

    // Generate QR code URL for scanning
    let qr_code_url = totp.get_url();

    Ok((secret_string, qr_code_url))
}

/// Verify a TOTP code against a stored secret.
pub fn verify_totp(secret: &str, code: &str) -> Result<(), AuthError> {
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(secret.to_string())
            .to_bytes()
            .map_err(|_| AuthError::InvalidTotpCode)?,
        None,
        String::new(),
    )
    .map_err(|_| AuthError::InvalidTotpCode)?;

    // Allow a window of ±1 time step for clock skew
    if !totp
        .check_current(code)
        .map_err(|_| AuthError::InvalidTotpCode)?
    {
        return Err(AuthError::InvalidTotpCode);
    }

    // Replay prevention: reject if this exact code was already accepted within
    // its ±1-step validity window (~90 s).  Uses the first 12 chars of the
    // encoded secret as a per-user namespace key without storing the full secret.
    #[cfg(feature = "server")]
    {
        use std::collections::HashMap;
        use std::sync::{Mutex, OnceLock};
        use std::time::{Duration, Instant};

        static USED_TOTP_CODES: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();

        let prefix_len = secret.len().min(12);
        let entry_key = format!("{}:{}", &secret[..prefix_len], code);
        let validity_window = Duration::from_secs(90); // ±1 step × 30 s

        let mut used = USED_TOTP_CODES
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .unwrap();

        let now = Instant::now();
        // Opportunistically prune expired entries on each call to bound memory use.
        used.retain(|_, inserted_at| now.duration_since(*inserted_at) < validity_window);

        if used.contains_key(&entry_key) {
            return Err(AuthError::InvalidTotpCode);
        }
        used.insert(entry_key, now);
    }

    Ok(())
}

/// TOTP manager for ease of use.
pub struct TotpManager;

impl TotpManager {
    /// Generate new TOTP credentials for user setup.
    pub fn generate_credentials(username: &str) -> Result<(String, String), AuthError> {
        generate_totp_secret(username, "Hosting Panel")
    }

    /// Verify a code during login.
    pub fn verify_code(secret: &str, code: &str) -> Result<(), AuthError> {
        verify_totp(secret, code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_totp_secret() {
        let (secret, qr_url) =
            TotpManager::generate_credentials("testuser").expect("Failed to generate TOTP secret");
        assert!(!secret.is_empty());
        assert!(qr_url.contains("otpauth://totp"));
    }
}
