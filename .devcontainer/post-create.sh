#!/bin/bash
set -euo pipefail

# Install system libraries needed for building
sudo apt-get update
sudo apt-get install -y libssl-dev libsqlite3-dev pkg-config

# Add the wasm32 target for Dioxus fullstack (client-side)
rustup target add wasm32-unknown-unknown

# Install Dioxus CLI
cargo install dioxus-cli

echo "✓ Dev environment ready. Run 'dx serve' to start the panel."
