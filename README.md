# Hosting Control Panel

A modern, open-source web hosting control panel written in **Rust** and **Dioxus 0.7**, designed as an alternative to cPanel.

## Features

- **Multi-Portal Architecture**: Separate admin, reseller, and client portals with role-based access control
- **Website Management**: Create and manage OpenLiteSpeed virtual hosts, PHP sites, and reverse proxies
- **SSL/TLS**: Automatic Let's Encrypt certificate management via Certbot
- **Database Management**: MariaDB support with user management
- **DNS Management**: Zone and record management via Cloudflare API
- **Email Services**: Postfix + Dovecot integration with mailbox and forwarder management
- **File Manager**: Web-based file management with upload/download support
- **Resource Monitoring**: Real-time CPU, RAM, disk, and bandwidth tracking
- **Firewall Management**: UFW integration with rule management
- **Audit Logging**: Complete audit trail of all administrative actions
- **2FA Support**: TOTP-based two-factor authentication
- **White-Label Branding**: Customizable panel for resellers

## Technology Stack

- **Language**: Rust (latest stable)
- **Frontend**: Dioxus 0.7 (fullstack mode with WASM)
- **Backend**: Dioxus server functions + Axum
- **Async Runtime**: Tokio
- **Database**: SQLite with SQLx (async, compile-time checked)
- **Authentication**: JWT tokens + Argon2id password hashing
- **Web Server**: OpenLiteSpeed (LiteSpeed PHP + LSAPI)
- **SSL**: Certbot with Let's Encrypt
- **DNS**: Cloudflare (API)
- **Email**: Postfix + Dovecot
- **Styling**: Tailwind CSS with Glassmorphism design

## System Requirements

- **OS**: Ubuntu 24.04 LTS (other Ubuntu versions may work but are not officially supported)
- **CPU**: 2+ cores recommended
- **RAM**: 2GB minimum (4GB+ recommended for production)
- **Disk**: 20GB+ free space
- **Network**: Static IP address recommended
- **Ports**: 80, 443 (HTTP/HTTPS), 3030 (panel), 465, 993 (mail)

## Installation

### Quick Install (Recommended)

The fastest way to deploy the panel is to download a pre-built binary from GitHub Releases. No Rust toolchain or build tools are required.

```bash
curl -fsSL https://raw.githubusercontent.com/damiencal/panel/main/install.sh | sudo bash
```

Or, if you prefer to clone the repo first:

```bash
git clone https://github.com/damiencal/panel.git
cd panel
sudo bash install.sh
```

The installation script will:
1. Update system packages
2. Install runtime dependencies (curl, openssl, ca-certificates, etc.)
3. Install OpenLiteSpeed, MariaDB, Postfix, Dovecot, and Pure-FTPd
4. Download and verify the pre-built `panel` binary from GitHub Releases
5. Configure all services
6. Create a systemd service
7. Initialize the database

> **Supported architectures:** `x86_64` and `aarch64` (ARM64).
> Use `--version=vX.Y.Z` to pin a specific release, e.g. `sudo bash install.sh --version=v1.0.0`.

### Build from Source

For developers, or on architectures not covered by the pre-built binaries:

```bash
# Clone the repository
git clone https://github.com/damiencal/panel.git
cd panel

# Run the installer in source mode (installs Rust and builds the binary)
sudo bash install.sh --from-source
```

You can also build manually:

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev libsqlite3-dev git curl

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env

# Clone and build
git clone https://github.com/damiencal/panel.git
cd panel
dx build --release

# Run
./target/dx/panel/release/web/panel
```

## Development

### Prerequisites

- Rust 1.75+
- Dioxus CLI: `cargo install dioxus-cli`

### Setup

```bash
# Clone repository
git clone https://github.com/damiencal/panel.git
cd panel

# Set up environment
cp .env.example .env

# Initialize database
cargo sqlx database create
cargo sqlx migrate run

# Run development server with hot reload
dx serve
```

The development server will be available at `http://localhost:3030` with frontend at `http://localhost:8080`.

### Project Structure

```
panel/
├── src/
│   ├── main.rs               # Entry point
│   ├── app.rs                # Root Dioxus component
│   ├── auth/                 # JWT, TOTP, role guards
│   ├── models/               # Shared data types
│   ├── db/                   # Database layer
│   ├── services/             # System service managers
│   ├── utils/                # Helpers & validators
│   └── ui/                   # Dioxus components
├── migrations/               # SQLx database migrations
├── templates/                # Config file templates
├── assets/                   # CSS, fonts, images
├── Cargo.toml               # Rust dependencies
├── Dioxus.toml              # Dioxus configuration
├── install.sh               # Installation script
└── panel.service            # systemd unit file
```

### Running Tests

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test models::user::tests::test_admin_can_access_everything
```

### Code Quality

```bash
# Format code
cargo fmt

# Check for warnings
cargo clippy -- -D warnings

# Run with test coverage
cargo tarpaulin
```

## Configuration

The panel is configured via `panel.toml`. Example:

```toml
[server]
host = "0.0.0.0"
port = 3030
secret_key = "your-secure-key-here"

[database]
url = "sqlite:/var/lib/panel/panel.db"

[openlitespeed]
config_dir = "/usr/local/lsws/conf"
vhost_dir = "/usr/local/lsws/conf/vhosts"
lsphp_bin = "/usr/local/lsws/lsphp83/bin/lsphp"

[certbot]
path = "/usr/bin/certbot"
webroot = "/usr/local/lsws/html"
```

### Environment Variables

```bash
DATABASE_URL=sqlite:panel.db
PANEL_PORT=3030
PANEL_HOST=0.0.0.0
PANEL_SECRET_KEY=your-secret-key
RUST_LOG=info,panel=debug
```

## Architecture

### Multi-Portal Access Control

The panel implements three distinct portals with role-based hierarchy:

**Admin**
- Full server control and monitoring
- Manage resellers and clients
- Create global hosting packages
- Access all resources
- Impersonate any user

**Reseller**
- Manage own clients
- Create packages within quotas
- View client resources (sites, databases, DNS)
- View support tickets from clients
- Apply white-label branding

**Client**
- Manage own websites, databases, DNS, email
- File manager for own sites
- Backup/restore capabilities
- View resource usage
- Submit support tickets

### Security Architecture

1. **Authentication**: JWT tokens with configurable expiry (default 24 hours)
2. **Authorization**: Role-based access control (RBAC) enforced server-side
3. **Password Hashing**: Argon2id with secure random salts
4. **2FA**: TOTP-based (compatible with Google Authenticator, Authy, etc.)
5. **CSRF Protection**: Built into Dioxus server functions
6. **Input Validation**: All user inputs validated and sanitized before system commands
7. **Audit Logging**: Every administrative action logged with user, timestamp, and result
8. **Ownership Verification**: Server-side checks ensure users can only access their own resources

### Database Schema

The panel uses SQLite with 11 core tables:
- `users` - User accounts with role, parent, and branding info
- `packages` - Hosting package definitions
- `resource_quotas` - Resource limits per user
- `sites` - OpenLiteSpeed virtual hosts
- `databases` - Database instances
- `database_users` - Database user accounts
- `dns_zones` - DNS zones
- `dns_records` - DNS records
- `email_domains` - Email domains
- `mailboxes` - Email mailbox accounts
- `support_tickets` & `ticket_messages` - Support system
- `audit_logs` - Action audit trail
- `usage_logs` - Bandwidth/storage tracking

See [migrations/](migrations/) for complete schema.

## API & Server Functions

The panel uses Dioxus server functions for all backend operations. Example:

```rust
#[server(CreateSite)]
async fn create_site(
    domain: String,
    site_type: SiteType,
) -> Result<Site, ServerFnError> {
    let user = require_auth().await?;
    // Create site logic
    Ok(site)
}
```

Server functions are:
- Type-safe
- Automatically serialized/deserialized
- Protected by authentication guards
- Logged for audit purposes

## Deployment

### Production Checklist

- [ ] Generate strong secret key: `openssl rand -base64 32`
- [ ] Set `PANEL_SECRET_KEY` environment variable
- [ ] Configure firewall rules (UFW or iptables)
- [ ] Set up SSL certificate for panel domain
- [ ] Configure reverse proxy (optional, if not using direct access)
- [ ] Enable automatic backups
- [ ] Set up monitoring/alerting
- [ ] Review and harden security settings
- [ ] Train administrators

### Systemd Service

Start/stop the panel via systemd:

```bash
# Start
sudo systemctl start panel

# Stop
sudo systemctl stop panel

# Restart
sudo systemctl restart panel

# Enable on boot
sudo systemctl enable panel

# View logs
sudo journalctl -u panel -f
```

### Reverse Proxy Setup (Optional)

If running behind a reverse proxy (Nginx, OpenLiteSpeed):

```nginx
server {
    listen 443 ssl http2;
    server_name panel.yourdomain.com;
    
    location / {
        proxy_pass http://localhost:3030;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Troubleshooting

### Panel won't start
```bash
# Check logs
sudo journalctl -u panel -n 50

# Check if port is in use
sudo lsof -i :3030

# Run manually for debugging
sudo /opt/panel/panel
```

### Database issues
```bash
# Check database file
ls -la /var/lib/panel/panel.db

# Reset database (WARNING: deletes data)
sudo rm /var/lib/panel/panel.db
sudo systemctl restart panel
```

### Permission issues
```bash
# Fix panel directory permissions
sudo chown -R panel:panel /var/lib/panel /var/log/panel /opt/panel
chmod -R 750 /var/lib/panel /var/log/panel /opt/panel
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit changes: `git commit -am 'Add your feature'`
4. Push to branch: `git push origin feature/your-feature`
5. Create a Pull Request

All contributions are subject to the contributor agreement in [CLA.md](CLA.md). Before opening a pull request, read [CONTRIBUTING.md](CONTRIBUTING.md) and include the required CLA confirmation statement in your PR body.

### Code Standards

- Run `cargo fmt` before committing
- Ensure `cargo clippy -- -D warnings` passes
- Write tests for new functionality
- Document public functions and modules

## Landing Page (GitHub Pages)

A static marketing/landing page lives in the [`/landing`](landing/) folder and is
automatically deployed to **GitHub Pages** on every push to `main` that touches
files inside that folder.

### How it works

The [`deploy-pages`](.github/workflows/deploy-pages.yml) GitHub Actions workflow:

1. Triggers on `push` to `main` when anything in `landing/` changes (also manually via `workflow_dispatch`).
2. Uploads the entire `landing/` folder as the Pages artifact.
3. Deploys it using the official `actions/deploy-pages` action.

### Enabling GitHub Pages

Before the first deployment succeeds you must configure the Pages source in your
repo settings **once**:

1. Go to **Settings → Pages** in your GitHub repository.
2. Under **Build and deployment → Source**, select **GitHub Actions**.
3. Save. The next push to `main` (or a manual trigger) will deploy the page.

### Editing the landing page

The page is fully self-contained in [`landing/index.html`](landing/index.html) —
one file with inline CSS and plain JavaScript, no build step required.

| What to change | Where to look in `index.html` |
|---|---|
| Project name / tagline | `<h1 class="hero__title">` |
| Hero CTA link | `href="https://github.com/damiencal/panel"` (three places) |
| Feature cards | `<div class="features-grid">` section |
| Screenshots | Replace `<div class="gallery__preview">` blocks with `<img>` tags |
| Installation commands | `<div class="install__snippet">` blocks |
| Footer links | `<div class="footer__grid">` section |
| Colour scheme | CSS custom properties at the top of `<style>` (`:root { … }`) |

## License

This repository uses a dual-licensing model:

- Community edition: GNU Affero General Public License v3.0 in [LICENSE](LICENSE)
- Alternative licensing policy: [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md)

The AGPL applies to the community code published in this repository. The copyright owner may also grant GPLv3 licenses to specific requesters by separate written permission. The `Multi-Server Cloud Service` feature is reserved for separate commercial licensing by the copyright owner unless a specific implementation is explicitly released under AGPL or expressly included in a separate written grant.
## Support

- **Documentation**: See [docs/](docs/) directory
- **Issues**: Report bugs on [GitHub Issues](https://github.com/damiencal/panel/issues)
- **Discussions**: Join [GitHub Discussions](https://github.com/damiencal/panel/discussions)

## Roadmap

- [ ] Backup/restore functionality
- [ ] Automatic license checking
- [ ] Email integration for notifications
- [ ] Advanced resource monitoring dashboard
- [ ] Multi-server management
- [ ] API for third-party integrations
- [ ] Mobile app
- [ ] Database replication support

## Security Disclosure

If you discover a security vulnerability, please email security@example.com instead of using the issue tracker.

## Acknowledgments

Built with ❤️ using Rust and Dioxus
