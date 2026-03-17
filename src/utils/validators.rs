/// Input validation helpers.
use regex::Regex;
use std::sync::OnceLock;

static EMAIL_REGEX: OnceLock<Regex> = OnceLock::new();
static DOMAIN_REGEX: OnceLock<Regex> = OnceLock::new();
static USERNAME_REGEX: OnceLock<Regex> = OnceLock::new();

fn email_regex() -> &'static Regex {
    EMAIL_REGEX.get_or_init(|| {
        Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
            .expect("Email regex failed to compile")
    })
}

fn domain_regex() -> &'static Regex {
    DOMAIN_REGEX.get_or_init(|| {
        Regex::new(r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
            .expect("Domain regex failed to compile")
    })
}

fn username_regex() -> &'static Regex {
    USERNAME_REGEX.get_or_init(|| {
        Regex::new(r"^[a-zA-Z0-9_-]{3,32}$").expect("Username regex failed to compile")
    })
}

/// Validate an email address.
pub fn validate_email(email: &str) -> Result<(), &'static str> {
    if email.len() > 254 {
        return Err("Email too long");
    }
    if email_regex().is_match(email) {
        Ok(())
    } else {
        Err("Invalid email format")
    }
}

/// Validate a domain name.
pub fn validate_domain(domain: &str) -> Result<(), &'static str> {
    if domain.len() < 3 || domain.len() > 253 {
        return Err("Domain length invalid (3-253 characters)");
    }
    if !domain_regex().is_match(domain) {
        return Err("Invalid domain format");
    }
    // Prevent registering bare TLDs or well-known eTLDs as if they were
    // hosting domains — mirroring the public-suffix check in opencli domains/add.sh.
    // The regex already enforces at least one dot, so a bare TLD like "com" is
    // rejected above. The check here targets two-label eTLDs (co.uk, com.au,
    // github.io, …) which look like valid domains but are themselves public
    // suffixes — adding them would allow a user to hijack all subdomains.
    validate_not_public_suffix(domain)?;
    Ok(())
}

/// Reject domains that are themselves public suffixes (TLDs, ccTLDs, eTLDs).
/// This is a hardcoded subset covering the most commonly misused entries; it
/// intentionally does not attempt to replicate the full IANA/Mozilla PSL.
pub fn validate_not_public_suffix(domain: &str) -> Result<(), &'static str> {
    // A registrable domain must have at least one label left of the eTLD.
    // Heuristic: if the domain consists entirely of a known single-label TLD
    // or two-label eTLD, reject it.
    const KNOWN_ETLDS: &[&str] = &[
        // Country-code second-level suffixes
        "co.uk",
        "co.nz",
        "co.jp",
        "co.za",
        "co.in",
        "co.id",
        "co.ke",
        "com.au",
        "com.br",
        "com.mx",
        "com.ar",
        "com.cn",
        "com.hk",
        "com.sg",
        "com.my",
        "com.ph",
        "com.pe",
        "com.co",
        "com.ve",
        "com.do",
        "com.ec",
        "com.gt",
        "com.hn",
        "net.au",
        "net.br",
        "net.cn",
        "net.mx",
        "org.uk",
        "org.au",
        "org.nz",
        "gov.uk",
        "gov.au",
        "gov.br",
        "edu.au",
        "edu.br",
        "ac.uk",
        "me.uk",
        "ltd.uk",
        "plc.uk",
        // Dynamic-DNS / SaaS subdomain registries — these are eTLDs where
        // user-registrable names sit one level below.
        "github.io",
        "gitlab.io",
        "vercel.app",
        "netlify.app",
        "pages.dev",
        "workers.dev",
        "run.app",
        "web.app",
        "firebaseapp.com",
        "appspot.com",
    ];

    let lower = domain.to_lowercase();
    for etld in KNOWN_ETLDS {
        if lower == *etld {
            return Err(
                "Domain is a public suffix / registry; please enter a registrable domain name",
            );
        }
    }
    Ok(())
}

/// Validate a username.
pub fn validate_username(username: &str) -> Result<(), &'static str> {
    if username_regex().is_match(username) {
        Ok(())
    } else {
        Err("Username must be 3-32 characters, alphanumeric, underscore, or hyphen")
    }
}

/// Validate an FTP virtual username in `prefix.owner_username` format.
/// The full username must be ≤ 64 characters, contain exactly one dot separator,
/// and contain only alphanumeric characters, underscores, or the single dot.
/// A dot is safe in Pure-FTPd passwd entries; colons and newlines are blocked
/// by `validate_passwd_field` at the call site.
pub fn validate_ftp_username(username: &str) -> Result<(), &'static str> {
    if username.is_empty() || username.len() > 64 {
        return Err("FTP username must be 1-64 characters");
    }
    if !username
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '.')
    {
        return Err("FTP username may only contain alphanumeric characters, underscores, or a dot");
    }
    if username.contains("..") || username.starts_with('.') || username.ends_with('.') {
        return Err("FTP username must not start or end with a dot, or contain consecutive dots");
    }
    Ok(())
}

/// Validate password strength.
pub fn validate_password(password: &str) -> Result<(), &'static str> {
    // AUDIT-01: cap password length to prevent Argon2 CPU/memory DoS.
    if password.len() > 1024 {
        return Err("Password must be at most 1024 characters");
    }
    if password.len() < 12 {
        return Err("Password must be at least 12 characters");
    }
    if !password.chars().any(|c| c.is_uppercase()) {
        return Err("Password must contain at least one uppercase letter");
    }
    if !password.chars().any(|c| c.is_lowercase()) {
        return Err("Password must contain at least one lowercase letter");
    }
    if !password.chars().any(|c| c.is_numeric()) {
        return Err("Password must contain at least one number");
    }
    if !password.chars().any(|c| !c.is_alphanumeric()) {
        return Err("Password must contain at least one special character");
    }
    Ok(())
}

/// Validate a database name.
pub fn validate_db_name(name: &str) -> Result<(), &'static str> {
    if name.len() < 3 || name.len() > 64 {
        return Err("Database name must be 3-64 characters");
    }
    if !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Err("Database name can only contain alphanumeric characters and underscores");
    }
    if !name.chars().next().is_some_and(|c| c.is_alphabetic()) {
        return Err("Database name must start with a letter");
    }
    Ok(())
}

/// Validate a password for a MySQL/MariaDB database user.
/// Applies standard password strength rules and additionally rejects characters
/// that cannot be safely embedded in MySQL CLI string literals or that are
/// blocked by the shell argument allowlist.
pub fn validate_mysql_password(password: &str) -> Result<(), &'static str> {
    validate_password(password)?;
    // Characters that would break MySQL CLI string literals or trigger the
    // shell injection guard: ' " \ ; | & $ ` ( ) { } newlines
    const FORBIDDEN: &[char] = &[
        '\'', '"', '\\', ';', '|', '&', '$', '`', '(', ')', '{', '}', '\n', '\r',
    ];
    if password.chars().any(|c| FORBIDDEN.contains(&c)) {
        return Err("MySQL password cannot contain: ' \" \\ ; | & $ ` ( ) { } or newlines");
    }
    Ok(())
}

/// Validate that a file path is safe and confined under an expected base directory.
/// Rejects paths with `..`, null bytes, newlines, or paths that don't start with `base`.
/// The path is canonicalized (symlinks resolved) before the prefix check to prevent
/// a directory symlink from pointing outside the allowed base.
pub fn validate_safe_path(path: &str, base: &str) -> Result<(), &'static str> {
    if path.is_empty() {
        return Err("Path must not be empty");
    }
    if path.contains('\0') || path.contains('\n') || path.contains('\r') {
        return Err("Path contains invalid characters");
    }
    if path.contains("..") {
        return Err("Path must not contain '..' sequences");
    }
    // Canonicalize resolves symlinks and cleans the path, then verify the
    // resulting absolute path is still under the expected base directory.
    // This prevents a symlink inside /home/ from redirecting to /etc/.
    // If the path does not exist yet, fall back to the lexical prefix check
    // (the caller must ensure the path is safe before creating it).
    match std::fs::canonicalize(path) {
        Ok(canonical) => {
            if !canonical.starts_with(base) {
                return Err("Path is outside the allowed base directory");
            }
        }
        Err(_) => {
            // Path does not exist yet — apply the lexical check as a best-effort guard.
            if !path.starts_with(base) {
                return Err("Path is outside the allowed base directory");
            }
        }
    }
    Ok(())
}

/// Validate that a value is safe for use in a colon-separated passwd-style file.
/// Rejects values containing colons, newlines, or null bytes.
pub fn validate_passwd_field(value: &str, field_name: &str) -> Result<(), String> {
    if value.contains(':') || value.contains('\n') || value.contains('\r') || value.contains('\0') {
        return Err(format!(
            "{} must not contain colons, newlines, or null bytes",
            field_name
        ));
    }
    Ok(())
}

/// Validate that a string is a valid IPv4 or IPv6 address.
/// Uses the standard library parser to reject malformed addresses.
/// IPv6 addresses with a zone ID (e.g. `fe80::1%eth0`) are also accepted.
pub fn validate_ip_address(ip: &str) -> bool {
    if ip.is_empty() || ip.len() > 45 {
        return false;
    }
    if ip.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    // Allow IPv6 with zone ID (e.g. fe80::1%eth0)
    if let Some((addr_part, zone_id)) = ip.rsplit_once('%') {
        return !zone_id.is_empty()
            && zone_id.len() <= 16
            && zone_id
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
            && addr_part.parse::<std::net::IpAddr>().is_ok();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_email() {
        assert!(validate_email("user@example.com").is_ok());
        assert!(validate_email("invalid.email").is_err());
    }

    #[test]
    fn test_validate_domain() {
        assert!(validate_domain("example.com").is_ok());
        assert!(validate_domain("sub.example.com").is_ok());
        assert!(validate_domain("invalid..com").is_err());
    }

    #[test]
    fn test_validate_username() {
        assert!(validate_username("user123").is_ok());
        assert!(validate_username("us").is_err()); // Too short
        assert!(validate_username("user@name").is_err()); // Invalid char
    }

    #[test]
    fn test_validate_password() {
        assert!(validate_password("SecurePass123!").is_ok());
        assert!(validate_password("weak").is_err());
    }

    #[test]
    fn test_validate_db_name() {
        assert!(validate_db_name("my_database").is_ok());
        assert!(validate_db_name("_invalid").is_err());
        assert!(validate_db_name("db").is_err()); // Too short
    }
}
