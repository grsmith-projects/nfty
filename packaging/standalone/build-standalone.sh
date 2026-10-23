#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

export PATH="$HOME/.cargo/bin:$PATH"

echo "==> Building standalone optimized release binary..."
cargo build --release

mkdir -p dist/standalone
cp target/release/nfty dist/standalone/nfty
strip dist/standalone/nfty || true
echo -n "" > dist/standalone/Nftyfile
cp packaging/standalone/nfty.service dist/standalone/nfty.service

tar -czf dist/nfty-standalone-linux-x86_64.tar.gz -C dist/standalone .

echo "==> Standalone package ready:"
echo "    Binary:  dist/standalone/nfty"
echo "    Archive: dist/nfty-standalone-linux-x86_64.tar.gz"
