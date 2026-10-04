#!/usr/bin/env bash
# Build the Rust FFI static library for both architectures and merge with lipo.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
# Intel support was dropped on 2026-10-04; this now produces the Apple Silicon release library only.
cargo build --release -p recovery-ffi --target aarch64-apple-darwin
mkdir -p target/universal
cp target/aarch64-apple-darwin/release/librecovery_ffi.a target/universal/librecovery_ffi.a
lipo -info target/universal/librecovery_ffi.a
