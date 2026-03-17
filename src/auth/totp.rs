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

/// Verify a TOTP code against a stored secret, with SQLite-backed replay prevention.
///
/// Uses the database to persist used codes across process restarts so that a
/// restart immediately after a successful login cannot be abused to replay the
/// same TOTP code.
#[cfg(feature = "server")]
pub async fn verify_totp_persistent(
    pool: &sqlx::SqlitePool,
    secret: &str,
    code: &str,
) -> Result<(), AuthError> {
    let totp = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        totp_rs::Secret::Encoded(secret.to_string())
            .to_bytes()
            .map_err(|_| AuthError::InvalidTotpCode)?,
        None,
        String::new(),
    )
    .map_err(|_| AuthError::InvalidTotpCode)?;

    if !totp
        .check_current(code)
        .map_err(|_| AuthError::InvalidTotpCode)?
    {
        return Err(AuthError::InvalidTotpCode);
    }

    // Replay prevention: use SQLite so the seen-codes set survives process restarts.
    // Key = SHA-256(secret)[0..16] hex + ":" + code, to avoid collisions that
    // would arise from using only the first 12 Base32 chars of the secret.
    use sha2::{Digest, Sha256};
    let secret_hash = hex::encode(&Sha256::digest(secret.as_bytes())[..16]);
    let entry_key = format!("{}:{}", secret_hash, code);
    let validity_window_secs: i64 = 90; // ±1 step × 30 s
    let now = chrono::Utc::now();
    let cutoff = (now - chrono::Duration::seconds(validity_window_secs)).to_rfc3339();

    // Purge expired entries first to keep the table small.
    let _ = sqlx::query("DELETE FROM used_totp_codes WHERE used_at < ?")
        .bind(&cutoff)
        .execute(pool)
        .await;

    // Attempt to insert — if the key already exists the UNIQUE constraint fires,
    // meaning this code was already used within the validity window (replay attack).
    let result = sqlx::query("INSERT INTO used_totp_codes (code_key, used_at) VALUES (?, ?)")
        .bind(&entry_key)
        .bind(now.to_rfc3339())
        .execute(pool)
        .await;

    match result {
        Ok(_) => Ok(()),
        Err(sqlx::Error::Database(ref db_err))
            if db_err.kind() == sqlx::error::ErrorKind::UniqueViolation =>
        {
            Err(AuthError::InvalidTotpCode)
        }
        Err(_) => {
            // DB failures must be treated as hard rejections to prevent a
            // DB-outage window from turning into a TOTP replay bypass.
            tracing::error!("TOTP replay-cache DB error — rejecting to prevent replay window");
            Err(AuthError::InvalidTotpCode)
        }
    }
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
            .unwrap_or_else(|poisoned| poisoned.into_inner());

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
