# Development Container Setup

This directory contains the VS Code Development Container configuration for the Hosting Control Panel project.

## Quick Start

### Prerequisites

- **Docker Desktop** installed and running
- **VS Code** with "Dev Containers" extension (ms-vscode-remote.remote-containers)

### Opening in Container

1. **Open the project in VS Code**
   ```bash
   code /Users/damiencal/Documents/web.com.do
   ```

2. **Reopen in Container**
   - Press `Ctrl+Shift+P` (or `Cmd+Shift+P` on Mac)
   - Type "Dev Containers: Reopen in Container"
   - Press Enter

3. **Wait for setup** (~2-5 minutes first time)
   - Container builds and installs dependencies
   - VS Code extensions install automatically
   - Post-create scripts run (database setup, etc.)

4. **Start developing**
   ```bash
   cargo run
   ```

## What's Included

### System Tools
- **Rust** (stable) with rustup, cargo
- **Build Tools**: gcc, clang, llvm, pkg-config, make
- **Development**: git, git-lfs, curl, wget, ssh, gnupg
- **Utilities**: vim, nano, tmux, htop, tree, ripgrep, fd, bat

### Rust Components
- **Toolchain**: Stable Rust with formatter, clippy, rust-analyzer
- **Tools**: cargo-watch, cargo-tarpaulin, cargo-expand, sqlx-cli
- **Extensions**: rust-analyzer server, LLDB debugger

### VS Code Extensions
- **Rust**: rust-analyzer, LLDB debugger, crates explorer, TOML editing
- **Dioxus**: Dioxus DX extension
- **Database**: SQLite viewer/editor
- **Git**: GitLens for git integration, GitHub Copilot
- **Formatting**: Prettier, Ruff linter
- **Docker**: Docker explorer and management
- **Other**: Markdown tools, YAML support, Hex viewer

### Databases (Optional)
- **SQLite**: Built-in, with sqlite3 CLI and admin web UI
- **MySQL**: Available via docker compose (not auto-started)
- **PostgreSQL**: Available via docker compose (not auto-started)

## Common Commands in Container

### Building & Running
```bash
# Build the project
cargo build

# Run with optimizations
cargo build --release

# Run development server (with hot reload)
cargo run

# Watch for changes and rebuild
cargo watch -x build

# Watch and run
cargo watch -x run
```

### Testing
```bash
# Run all tests
cargo test

# Run specific test
cargo test test_name

# Run with output
cargo test -- --nocapture

# Generate coverage
cargo tarpaulin --out Html
```

### Code Quality
```bash
# Format code
cargo fmt

# Check for issues
cargo clippy

# Fix common issues automatically
cargo clippy --fix --allow-dirty
```

### Database
```bash
# Create database
sqlx database create

# Run migrations
sqlx migrate run

# Add new migration
sqlx migrate add -r migration_name

# Check database
sqlite3 panel.db
```

### Development Tools
```bash
# Open cargo docs
cargo doc --open

# Expand macros (debug)
cargo expand

# Check binary size
cargo bloat --release
```

## Docker Compose Commands

### Start Just the Container
```bash
# From .devcontainer directory or use VS Code UI
docker-compose up -d
```

### Optional: Start with SQLite Admin UI
```bash
# Starts SQLite web admin UI on localhost:8081
docker-compose --profile tools up -d sqliteadmin
```

### View Logs
```bash
docker-compose logs -f dev
```

### Stop Container
```bash
docker-compose down
```

### Clean Up Everything
```bash
docker-compose down -v
```

## Port Forwarding

The following ports are automatically forwarded from container to host:

| Port | Service | Auto-Forward |
|------|---------|--------------|
| 3030 | Panel App | Notify |
| 3306 | MySQL | Silent |
| 5432 | PostgreSQL | Silent |
| 8080 | OpenLiteSpeed | Silent |
| 8081 | SQLite Admin | (optional tool) |

You can access your development app at `http://localhost:3030`

## Customization

### Add VS Code Extension
Edit `devcontainer.json` -> `customizations.vscode.extensions`:
```json
"extensions": [
  "existing.extension",
  "new.extension"
]
```
Then rebuild container with "Dev Containers: Rebuild Container"

### Add Environment Variable
Edit `docker-compose.yml` -> `services.dev.environment`:
```yaml
environment:
  NEW_VAR: "value"
```

### Add Build Dependency
Edit `Dockerfile` and add to `apt-get install`:
```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends \
    # ... existing packages
    new-package \
    && rm -rf /var/lib/apt/lists/*
```

Then rebuild: `Dev Containers: Rebuild Container`

## Performance Optimization

### If container is slow on Mac/Windows

The default setup uses `:cached` volumes which are optimized for your OS:

```yaml
volumes:
  - ..:/workspace:cached  # Host → Container is cached
  - /var/run/docker.sock:/var/run/docker.sock
  - vscode-extensions:/home/vscode/.vscode-server/extensions
  - cargo-cache:/home/vscode/.cargo
  - rust-build:/workspace/target  # Build artifacts stay in container
```

If still slow, try:
1. Use Docker Desktop's resource settings (allocate more CPU/RAM)
2. Clean up build artifacts: `cargo clean`
3. Restart Docker: `docker system prune -a`

### Tip: Keep build artifacts in container
The target/ directory is a named volume (`rust-build`) to avoid slow syncing of build outputs on Mac/Windows.

## Troubleshooting

### Container won't start
```bash
# Check logs
docker-compose logs dev

# Rebuild container
# VS Code: "Dev Containers: Rebuild Container"
# Or: docker-compose build --no-cache
```

### Rust compiler is slow
```bash
# Increase Docker resource limits in Docker Desktop settings
# Recommended: 4+ CPUs, 8+ GB RAM
```

### Extensions not installing
```bash
# Rebuild container
# VS Code: "Dev Containers: Rebuild Container"
```

### Database errors
```bash
# Reset database
rm panel.db
sqlx database create
sqlx migrate run
```

### Permission issues
```bash
# The container runs as 'vscode' user (uid 1000)
# Ensure host files are readable: chmod 644 files
```

### Can't connect to services
```bash
# Make sure docker-compose is running:
docker-compose ps

# Check port forwarding:
docker-compose ports

# Services should be at: localhost:PORT
```

## Git Configuration

Your `.gitconfig` is automatically mounted into the container, so git commands work as expected with your configured user and credentials.

### SSH Keys
Your `.ssh` directory is available in read-only mode. Configure ssh-agent if needed.

## Remote Debugging

The container includes LLDB debugger. Set breakpoints in VS Code:

1. Run with `F5` or "Run and Debug"
2. Select "Rust (LLDB)" debugger
3. Set breakpoints by clicking on line numbers
4. Step through code

## Additional Resources

- [Dev Containers Documentation](https://code.visualstudio.com/docs/devcontainers/containers)
- [Rust Analyzer Guide](https://rust-analyzer.github.io/)
- [Dioxus Documentation](https://docs.dioxuslabs.com)

## Support

If you encounter issues:
1. Check `.devcontainer/post-create.sh` logs
2. Rebuild container and check build output
3. Review `DEVELOPMENT.md` for project-specific guidance
4. See `QUICK_START.md` for common tasks

---

Happy coding! 🚀
