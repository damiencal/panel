/// Authentication module: JWT tokens, TOTP/2FA, role-based access guards, and
/// cryptographic helpers for secret storage.
pub mod crypto;
pub mod guards;
pub mod jwt;
pub mod totp;

#[cfg(feature = "server")]
pub use crypto::{decrypt_totp_secret, encrypt_totp_secret, init_totp_enc_key};
pub use guards::{check_ownership, require_admin, require_auth, require_reseller};
pub use jwt::{create_token, verify_token, JwtManager};
#[cfg(feature = "server")]
pub use totp::verify_totp_persistent;
pub use totp::{generate_totp_secret, verify_totp, TotpManager};
