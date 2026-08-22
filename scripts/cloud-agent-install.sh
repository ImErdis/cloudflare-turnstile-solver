#!/usr/bin/env bash
set -euo pipefail

# Idempotent Cloud Agent install. Safe if this PR is not merged: every
# file-dependent command is guarded.

if command -v rustup >/dev/null 2>&1; then
  rustup toolchain install stable --profile minimal
  rustup default stable
fi

if [ -f Cargo.lock ]; then
  cargo fetch --locked
fi

if [ -f tools/js-re/package-lock.json ]; then
  npm ci --prefix tools/js-re
fi

if [ -f scripts/package-lock.json ]; then
  npm ci --prefix scripts
fi
