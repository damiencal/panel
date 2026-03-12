---
applyTo: "src/services/**"
description: "Defense-in-depth rules for service layer code that manages system services (web server, database, FTP, email, DNS). Applied to all files under src/services/."
---

# Service Layer Security Rules

Every function in `src/services/` operates at the OS level — executing shell commands, writing config files, and managing system users. **Every public function must validate its own inputs**, even if the caller (server function) also validates. This is defense-in-depth.

## Mandatory Input Validation

### Domain names
Call `crate::utils::validators::validate_domain()` at the top of any function that receives a domain parameter. Reject domains containing `..`, `/`, `\`, or null bytes.

### Usernames
Call `crate::utils::validators::validate_username()`. Never interpolate usernames into SQL, config files, or file paths without validation.

### Passwords
- **MySQL passwords**: Call `crate::utils::validators::validate_mysql_password()` before constructing any SQL string.
- **FTP/email passwords**: Must be hashed before storage. Never store plaintext passwords in passwd files.
- **Never pass passwords as CLI arguments** (visible in `ps aux`). Use stdin piping instead.

### File paths (doc_root, home_dir, etc.)
Always validate paths:
1. Must not contain `..` sequences
2. Must start with the expected base directory (e.g., `/home/`, `/var/mail/vhosts/`)
3. Use `std::path::Path` for construction, then canonicalize
4. Must not contain null bytes, newlines, or colons (for passwd-style files)

### Database names
Call `crate::utils::validators::validate_db_name()` before constructing any SQL.

### Email addresses
Call `crate::utils::validators::validate_email()` before using in file paths or config entries.

## Forbidden Patterns

### Never download and execute remote scripts
```rust
// FORBIDDEN — RCE risk
let script = reqwest::get(url).await?.text().await?;
Command::new("bash").arg("-c").arg(script).spawn()?;
```
Use `apt-get install` with the package repository pre-configured instead.

### Never use `std::process::Command` directly
Always use the `shell::exec()` helper which enforces the binary allowlist and argument validation. The only exception is the `shell` module itself.

### Never use `format!` to build SQL with user input
```rust
// FORBIDDEN — SQL injection risk
let sql = format!("CREATE USER '{}'@'localhost' IDENTIFIED BY '{}'", user, pass);
```
Use stdin piping to the `mysql` client, or use a proper database client library with parameterized queries.

### Never write config files without validating interpolated values
```rust
// FORBIDDEN — config injection risk
let config = format!("docRoot {}", doc_root);  // doc_root could contain newlines
```
Validate that interpolated values contain no newlines or config-special characters.

## File Modification Safety

### Use file locking for read-modify-write operations
When modifying shared config files (passwd files, postfix maps, dovecot users), use file locking to prevent TOCTOU race conditions:
```rust
use tokio::fs;
use std::os::unix::fs::OpenOptionsExt;

// Lock the file before read-modify-write
let lock = FileLock::exclusive(path).await?;
let content = fs::read_to_string(path).await?;
// ... modify ...
fs::write(path, new_content).await?;
drop(lock);
```

### Validate passwd-file field values
When constructing colon-separated passwd entries, ensure no field contains `:` or newlines, which would corrupt the file structure.

## Error Handling

- Never leak internal paths or system details in error messages returned to users
- Log detailed errors with `tracing::error!` but return generic messages to the client
- Always use `map_err` to sanitize `ServiceError` messages before they reach the HTTP layer
