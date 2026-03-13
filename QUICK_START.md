# Quick Start Guide

Get the hosting control panel up and running in seconds.

## Prerequisites

- Rust 1.75+ ([install](https://rustup.rs/))
- Git
- sqlite3 (usually pre-installed)

## Installation

### 1. Clone & Setup

```bash
git clone <repo-url>
cd web.com.do
cp .env.example .env
```

### 2. Run Migrations

```bash
# Install sqlx-cli if you don't have it
cargo install sqlx-cli --no-default-features --features sqlite

# Run migrations
sqlx migrate run
```

### 3. Build

```bash
dx build --release --platform web
```

The server binary and web assets will be at `target/dx/panel/release/web/`

### 4. Run

```bash
./target/dx/panel/release/web/panel
```

Visit `http://localhost:3030`

## Development Commands

```bash
# Format code
cargo fmt

# Check for issues
cargo clippy

# Run tests
cargo test

# Build docs
cargo doc --open

# Develop with hot reload
dx serve --hot-reload true

# Database operations
sqlx database create
sqlx migrate add -r <name>  # Create migration
sqlx migrate run             # Run migrations
```

## Common Tasks

### Add a New Page

1. Create component in `src/main.rs` (search for `#[component]`)
2. Add Route variant
3. Add SidebarLink in layout

### Add a New Database Table

1. Create migration: `sqlx migrate add -r create_<table>`
2. Write SQL in `migrations/<timestamp>_create_<table>.sql`
3. Add struct to `src/models/`
4. Add CRUD functions to `src/db/<table>.rs`
5. Run `sqlx migrate run`

### Add Server Function

Create in corresponding module:

```rust
#[server(FunctionName)]
async fn function_name(param: String) -> Result<String, ServerFnError> {
    // Implementation
    Ok("result".to_string())
}
```

### Call Server Function from UI

```rust
let data = function_name("param".to_string()).await?;
```

## Environment Variables

Key variables in `.env`:

```env
PANEL_BIND_HOST=0.0.0.0        # Listen on all interfaces
PANEL_BIND_PORT=3030            # Port number
PANEL_SECRET_KEY=...            # JWT secret (DO NOT commit)
DATABASE_URL=sqlite:panel.db    # Database location
RUST_LOG=debug,panel=trace      # Logging level
```

For secrets, use environment variables or `.env` file (never commit secrets).

## Testing

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_name

# With output
cargo test test_name -- --nocapture

# Only integration tests
cargo test --test '*'
```

## Debugging

### Enable Full Debug Logging

```bash
RUST_LOG=debug,panel=trace,dioxus=debug cargo run
```

### Check Database

```bash
sqlite3 panel.db
sqlite> .schema
sqlite> SELECT * FROM users;
```

### View Database Errors

Most errors will be logged. Check terminal output. For SQLx errors, enable SQLx debug logging:

```bash
RUST_LOG=sqlx=debug cargo run
```

## Project Structure

- `src/` - Application source code
- `migrations/` - Database migrations
- `templates/` - Configuration templates (Jinja2)
- `assets/` - CSS, tailwind config
- `.env` - Environment variables (DO NOT COMMIT)
- `Cargo.toml` - Dependencies and metadata

## Architecture Quick Reference

```
User Request
    ↓
Dioxus Server Function
    ↓
Authentication (JWT + Role Check)
    ↓
Authorization (Ownership Check)
    ↓
Database Query (SQLx)
    ↓
Response
```

## Important Files

| File | Purpose |
|------|---------|
| `src/models/` | Data structures |
| `src/auth/guards.rs` | Access control |
| `src/db/` | Database queries |
| `src/services/` | System services |
| `src/utils/validators.rs` | Input validation |
| `src/main.rs` | App routing & layout |

## Common Issues

**Database locked**
```
Solution: Close other database connections, restart application
```

**JWT secret not set**
```
Solution: Set PANEL_SECRET_KEY in .env with a random string
```

**Port already in use**
```
Solution: Change PANEL_BIND_PORT in .env or kill process:
lsof -i :3030
kill -9 <PID>
```

**SQLx compile errors**
```
Solution: Ensure DATABASE_URL is set and database exists
sqlx database create
```

## Deployment

For production, see `install.sh`:

```bash
sudo bash install.sh
```

This installs:
- Rust toolchain
- All dependencies (OpenLiteSpeed, MariaDB, etc.)
- Systemd service
- Firewall rules

## Documentation

- [Development Guide](DEVELOPMENT.md) - Architecture & patterns
- [README.md](README.md) - Full features & configuration
- [Dioxus Docs](https://docs.dioxuslabs.com/)
- [Rust Book](https://doc.rust-lang.org/book/)

## Getting Help

1. Check logs: `journalctl -u panel -f`
2. Enable debug logging: `RUST_LOG=debug`
3. Check database schema: `sqlx migrate info`
4. Review [DEVELOPMENT.md](DEVELOPMENT.md) for patterns

## Next Steps

1. ✅ Setup complete! Run `cargo run`
2. Create a user account (login page)
3. Add first site (Sites page)
4. Configure DNS records
5. Set up SSL certificate

Happy coding! 🚀
