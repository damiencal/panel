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
    if domain_regex().is_match(domain) {
        Ok(())
    } else {
        Err("Invalid domain format")
    }
}

/// Validate a username.
pub fn validate_username(username: &str) -> Result<(), &'static str> {
    if username_regex().is_match(username) {
        Ok(())
    } else {
        Err("Username must be 3-32 characters, alphanumeric, underscore, or hyphen")
    }
}

/// Validate password strength.
pub fn validate_password(password: &str) -> Result<(), &'static str> {
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
    if !name.chars().next().unwrap().is_alphabetic() {
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
    if !path.starts_with(base) {
        return Err("Path is outside the allowed base directory");
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

/// Validate that a string is a plausible IPv4 or IPv6 address (no injection chars).
pub fn validate_ip_address(ip: &str) -> bool {
    if ip.is_empty() || ip.len() > 45 {
        return false;
    }
    // Must only contain characters valid in IP addresses: digits, dots, colons, hex letters, brackets
    ip.chars()
        .all(|c| c.is_ascii_hexdigit() || matches!(c, '.' | ':' | '[' | ']' | '%'))
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
