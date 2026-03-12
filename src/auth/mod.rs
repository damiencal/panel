pub mod guards;
/// Authentication module: JWT tokens, TOTP/2FA, and role-based access guards.
pub mod jwt;
pub mod totp;

pub use guards::{check_ownership, require_admin, require_auth, require_reseller};
pub use jwt::{create_token, verify_token, JwtManager};
pub use totp::{generate_totp_secret, verify_totp, TotpManager};
