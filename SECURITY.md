# Security Guide

Security is critical for a hosting control panel. This document outlines security practices and considerations.

## Authentication

### JWT Security

1. **Secret Management**
   - Store `PANEL_SECRET_KEY` in environment variables only
   - Never commit secrets to version control
   - Use strong random strings (minimum 32 characters)
   - Rotate regularly in production

2. **Token Lifetime**
   - Current: 24 hours
   - Consider shorter (4-8 hours) for sensitive operations
   - Implement refresh token pattern for longer sessions

3. **Token Verification**
   - Always verify token signature (done automatically)
   - Check expiration time
   - Validate claims structure

### Two-Factor Authentication (TOTP)

1. **Setup**
   - Users enable TOTP in account settings
   - Secret is stored encrypted in database
   - QR code shown only once during setup

2. **Verification**
   - Time window of ±1 step (60 seconds total)
   - Prevents replay attacks
   - Backup codes recommended (not yet implemented)

### Password Security

1. **Hashing**
   - Algorithm: Argon2id (current best practice)
   - Parameters: m=19456, t=2, p=1
   - Never store plaintext passwords
   - Never use MD5, SHA1, SHA256 for passwords

2. **Requirements**
   - Minimum 12 characters
   - Mix of uppercase, lowercase, numbers, special characters
   - Check against common passwords (future enhancement)

3. **Password Reset**
   - Use secure token (random, 32+ bytes)
   - Expires after 1 hour
   - One-time use only
   - Send via email with confirmation link

## Authorization & Access Control

### Role-Based Access Control (RBAC)

1. **Role Hierarchy**
   ```
   Admin (can do everything)
     └─ Reseller (can manage own clients)
           └─ Client (can manage own resources)
   ```

2. **Ownership Chains**
   - All resources have an owner_id
   - Resellers have clients via parent_id relationship
   - Database queries enforced by role

3. **Server Function Guards**
   ```rust
   #[server(UpdateSite)]
   async fn update_site(site_id: i64, name: String) -> Result<(), ServerFnError> {
       let user = require_auth().await?;
       
       // Check ownership based on role
       let site = db::sites::get(site_id).await?;
       check_ownership(&user, site.owner_id, site.reseller_id)?;
       
       // Perform update
       Ok(())
   }
   ```

4. **Testing**
   - Test that clients can't access other clients' resources
   - Test that resellers can't access other resellers' resources
   - Test that admins can access everything

### Principle of Least Privilege

1. **System User**
   - Panel runs as `panel:panel` user (not root)
   - Limited file permissions
   - Restricted sudoers rules if needed

2. **Database Permissions**
   - Single application user for database
   - No direct user access to database
   - Queries use parameterized statements

3. **File Permissions**
   - User home directories: 0750 (rwxr-x---)
   - Config files: 0640 (rw-r-----)
   - Logs: 0640
   - Secrets: 0600 (rw-------)

## Input Validation

### Validation Layers

1. **Frontend Validation**
   - HTML form constraints
   - Client-side JavaScript checks
   - **NOT TRUSTED** - always re-validate on server

2. **Server Validation**
   - All inputs validated before processing
   - Use `src/utils/validators.rs` functions
   - Return meaningful error messages

3. **Database Validation**
   - Schema constraints (NOT NULL, UNIQUE, CHECK)
   - Foreign key constraints
   - Trigger validation for business rules

### Validation Examples

```rust
// Email validation
validate_email("user@example.com")?;

// Domain validation (prevents directory traversal)
validate_domain("example.com")?;

// Username validation
validate_username("user_name123")?;

// Password validation
validate_password("MySecurePass123!")?;

// Database name validation
validate_db_name("my_database")?;
```

## SQL Injection Prevention

### Using SQLx (Safe by Default)

SQLx uses compile-time verified queries:

```rust
// ✅ SAFE - SQLx prevents injection
let user = sqlx::query_as::<_, User>(
    "SELECT * FROM users WHERE email = ?"
)
.bind(email) // Parameterized
.fetch_one(&pool)
.await?;

// ❌ NEVER - String interpolation
let query = format!("SELECT * FROM users WHERE email = '{}'", email);
sqlx::query_as::<_, User>(&query).fetch_one(&pool).await?;
```

### Rules

1. Always use parameterized queries with `.bind()`
2. Never interpolate user input with `format!()` or `+`
3. Use SQLx's compile-time verification
4. Run `cargo build` to verify queries at compile time

## Command Injection Prevention

### Shell Command Safety

The `services/mod.rs::shell::exec()` function uses an allowlist approach:

```rust
// Allowed binaries only (30+ whitelisted)
const ALLOWED_BINARIES: &[&str] = &[
    "systemctl", "lswsctrl", "certbot", "mariadb",
    "useradd", "userdel", "chown", "chmod", "ufw", "iptables",
    // ... more
];

// ✅ SAFE - Binary is in allowlist
exec("systemctl", &["restart", "lsws"])?;

// ❌ NEVER - User input in shell command
exec("sh", &["-c", format!("mkdir {}", user_input).as_str()])?;
```

### Rules

1. Use allowlist of safe binaries
2. Never pass user input as arguments
3. Use Command API, not shell -c
4. Validate inputs before constructing commands
5. Run as non-root when possible

## Cross-Site Scripting (XSS) Prevention

### Dioxus Safety

Dioxus automatically escapes HTML in component rendering:

```rust
// User input is automatically escaped
rsx! {
    div { "{user.username}" }  // ✅ SAFE - <script> tags will be visible
    div { dangerous_html(user.input) }  // ❌ Use sparingly, only trusted sources
}
```

### Rules

1. Use normal `{}` interpolation (auto-escaped)
2. Use `dangerous_html()` only for trusted content
3. Sanitize user input before storing
4. No `eval()` or dynamic code execution

## Cross-Site Request Forgery (CSRF) Prevention

### Dioxus Server Functions

Server functions are immune to CSRF attacks because they:
1. Require same-origin requests
2. Use request method validation
3. Include authentication token

### Best Practices

1. Use POST for state-changing operations
2. Require authentication on all sensitive functions
3. Consider CSRF tokens for sensitive operations (optional with server functions)
4. Set SameSite cookie attribute (Dioxus handles this)

## Data Protection

### Sensitive Data Handling

1. **In Transit**
   - Use HTTPS only (enforced via systemd reverse proxy)
   - TLS 1.2+ with strong ciphers
   - HSTS headers

2. **At Rest**
   - Database passwords: never stored, only hashed
   - TOTP secrets: consider encryption at rest
   - Logs: don't log passwords or secrets
   - Database backups: encrypt before storage

3. **In Memory**
   - Secrets cleared after use (Rust default)
   - Use secure string types when available
   - Be careful with debug logging of sensitive data

### PII Handling

1. Only collect necessary data
2. Store only for required retention period
3. Securely delete when no longer needed
4. Implement data export for users
5. Log access to sensitive data

## Logging & Monitoring

### Security Logging

Every security-relevant event is logged:

```rust
db::audit::log_action(
    &pool,
    admin_id,
    "user_created",          // action
    Some("user".to_string()),
    Some(new_user_id),
    Some(new_user_email),
    Some("Created by admin"), // description
    "Success",
    None,
    ip_address,
    None,  // impersonation
).await?;
```

### Log Analysis

Monitor for:
- Failed login attempts (multiple → lock account)
- Role escalation attempts
- Unauthorized access attempts
- Large data exports
- Configuration changes
- Service restarts

### Log Security

1. Store logs securely with restricted access
2. Don't log passwords, secrets, or PII unnecessarily
3. Keep logs for 90+ days for audit
4. Back up logs to separate location
5. Implement log aggregation (future enhancement)

## API Security

### Rate Limiting

Server functions can be rate limited:

```rust
use governor::{Quota, RateLimiter};

static RATE_LIMITER: Lazy<RateLimiter> = 
    Lazy::new(|| RateLimiter::direct(Quota::per_second(10)));

#[server(SensitiveFunction)]
async fn sensitive_function() -> Result<(), ServerFnError> {
    if RATE_LIMITER.check().is_err() {
        return Err(ServerFnError::new("Rate limited"));
    }
    Ok(())
}
```

### Timeouts

- Database queries: 30 second timeout
- Shell commands: 60 second timeout
- External API calls: 30 second timeout

## Network Security

### Firewall

The `install.sh` configures UFW:
- SSH (22): Restricted to admin IPs
- HTTP (80): Open
- HTTPS (443): Open
- MariaDB (3306): Restricted to localhost
- SMTPS (465): Implicit TLS, restricted to trusted IPs
- IMAPS (993): Implicit TLS, open
- FTP (21): Restricted to trusted IPs

### Systemd Hardening

Service runs with:
- PrivateTmp (isolated temp)
- NoNewPrivileges (can't gain privileges)
- ProtectSystem=strict (read-only filesystem)
- ProtectHome (home directory inaccessible)
- ReadWritePaths limited to necessary locations

## Security Checklist

### Development

- [ ] No hardcoded secrets in code
- [ ] All inputs validated
- [ ] All SQL queries parameterized
- [ ] All shell commands from allowlist
- [ ] Audit logging for sensitive operations
- [ ] Error messages don't leak information
- [ ] No debug logging of secrets
- [ ] All tests include security tests
- [ ] Access control tested thoroughly
- [ ] HTTPS redirect configured

### Deployment

- [ ] All secrets in environment variables
- [ ] Database backed up daily
- [ ] SSL certificate valid (check expiry)
- [ ] Firewall rules configured correctly
- [ ] SSH key authentication (no password)
- [ ] Regular security updates applied
- [ ] Intrusion detection configured
- [ ] Backups tested and working
- [ ] Incident response plan documented
- [ ] Security audit scheduled

### Operations

- [ ] Access logs reviewed regularly
- [ ] Failed login attempts monitored
- [ ] Configuration changes logged
- [ ] Secrets rotated quarterly
- [ ] Penetration testing annual
- [ ] Vulnerability scanning enabled
- [ ] Security patches applied promptly
- [ ] Disaster recovery tested
- [ ] Data retention policy enforced
- [ ] PII handling compliant

## Incident Response

### If Compromised

1. **Immediate**
   - Stop the service: `systemctl stop panel`
   - Change all secrets: `PANEL_SECRET_KEY`, database password
   - Review logs for unauthorized access
   - Revoke all active sessions

2. **Investigation**
   - Check audit logs for suspicious activity
   - Review database for unauthorized changes
   - Check system logs for privilege escalation
   - Analyze network traffic

3. **Recovery**
   - Restore from known-good backup
   - Redeploy with patched code
   - Reset all passwords
   - Notify affected users
   - Document incident

4. **Prevention**
   - Apply security patches
   - Update security policies
   - Conduct security training
   - Improve monitoring

## Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Rust Security](https://www.rust-lang.org/governance/security-disclosures/)
- [Web Security Academy](https://portswigger.net/web-security)
- [CWE List](https://cwe.mitre.org/)
- [NIST Cybersecurity](https://www.nist.gov/cybersecurity)

## Security Disclosure

If you discover a security vulnerability:

1. **Do NOT** open a public issue
2. Email security@example.com with details
3. Include reproduction steps if possible
4. Allow 90 days for remediation before disclosure
5. We will acknowledge within 48 hours

Thank you for helping keep this project secure!
