/// AES-256-GCM encryption helpers for sensitive secrets stored in the database.
///
/// Format: `v1:<base64url(12-byte nonce || ciphertext || 16-byte auth-tag)>`
///
/// The AES key is derived from the application's JWT signing secret via
/// HMAC-SHA256 with the label "totp-secret-encryption-v1", producing a
/// 32-byte key that is stored in a `OnceLock` and re-derived at most once per
/// process (SEC-31-03).
#[cfg(feature = "server")]
use crate::models::auth::AuthError;
#[cfg(feature = "server")]
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
#[cfg(feature = "server")]
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
#[cfg(feature = "server")]
use hmac::{Hmac, Mac};
#[cfg(feature = "server")]
use sha2::Sha256;
#[cfg(feature = "server")]
use std::sync::OnceLock;

#[cfg(feature = "server")]
static TOTP_ENC_KEY: OnceLock<[u8; 32]> = OnceLock::new();

/// Derive and cache the 32-byte AES-256 encryption key from the JWT master key.
/// The HMAC-SHA256 label ensures the AES key is domain-separated from the JWT
/// signing key.
#[cfg(feature = "server")]
pub fn init_totp_enc_key(jwt_master_secret: &str) {
    let _ = TOTP_ENC_KEY.get_or_init(|| {
        // HMAC-SHA256(master_secret, label) → 32-byte key
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(jwt_master_secret.as_bytes())
            .expect("HMAC accepts any key length");
        mac.update(b"totp-secret-encryption-v1");
        let result = mac.finalize().into_bytes();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    });
}

/// Return the cached AES key, initialising it from the JWT key if needed.
#[cfg(feature = "server")]
fn get_totp_enc_key() -> Result<[u8; 32], AuthError> {
    TOTP_ENC_KEY.get().copied().ok_or(AuthError::Internal(
        "TOTP encryption key not initialised".into(),
    ))
}

/// Encrypt a TOTP secret string and return a versioned, base64url-encoded blob
/// suitable for storage in the database.
///
/// Returns an error only if the underlying OS RNG fails (extremely rare).
#[cfg(feature = "server")]
pub fn encrypt_totp_secret(plaintext: &str) -> Result<String, AuthError> {
    let key_bytes = get_totp_enc_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|_| AuthError::Internal("AES key init failed".into()))?;

    // Generate a random 12-byte nonce.  Uniqueness is paramount for GCM;
    // 96 bits of OS randomness makes collision probability negligible even for
    // billions of encryptions.
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| AuthError::Internal("TOTP secret encryption failed".into()))?;

    // Serialise as: nonce(12) || ciphertext || tag(16)  (GCM appends the tag)
    let mut blob = Vec::with_capacity(12 + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    Ok(format!("v1:{}", URL_SAFE_NO_PAD.encode(&blob)))
}

/// Decrypt a TOTP secret previously produced by `encrypt_totp_secret`.
/// Returns `AuthError::InvalidTotpCode` on any decryption failure so callers
/// see the same error as a bad TOTP code (no oracle information).
#[cfg(feature = "server")]
pub fn decrypt_totp_secret(stored: &str) -> Result<String, AuthError> {
    let b64 = stored
        .strip_prefix("v1:")
        .ok_or(AuthError::InvalidTotpCode)?; // unrecognised version / plaintext

    let data = URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|_| AuthError::InvalidTotpCode)?;

    if data.len() < 12 + 16 {
        // Minimum: 12-byte nonce + 16-byte GCM tag (empty plaintext edge case)
        return Err(AuthError::InvalidTotpCode);
    }

    let (nonce_bytes, ciphertext_and_tag) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let key_bytes = get_totp_enc_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).map_err(|_| AuthError::InvalidTotpCode)?;

    let plaintext_bytes = cipher
        .decrypt(nonce, ciphertext_and_tag)
        .map_err(|_| AuthError::InvalidTotpCode)?;

    String::from_utf8(plaintext_bytes).map_err(|_| AuthError::InvalidTotpCode)
}
