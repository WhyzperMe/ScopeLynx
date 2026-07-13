#!/usr/bin/env sh
set -eu

command -v cargo >/dev/null 2>&1 || {
  echo "cargo was not found; install Rust through rustup first" >&2
  exit 1
}

cargo metadata --locked --format-version 1 >/dev/null
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo test --workspace --doc --all-features
cargo build --workspace --release --all-features

if command -v cargo-audit >/dev/null 2>&1; then
  cargo audit
else
  echo "warning: cargo-audit is not installed" >&2
fi

if command -v cargo-deny >/dev/null 2>&1; then
  cargo deny check
else
  echo "warning: cargo-deny is not installed" >&2
fi
