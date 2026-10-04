#!/usr/bin/env bash
# Local equivalent of CI (task 1.4). Fails on formatting, lint, test, license or sanitizer regressions.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
cargo fmt --all -- --check
cargo clippy --workspace --all-features --all-targets -- -D warnings
cargo test --workspace --all-features
python3 scripts/gen-licenses.py --check
if [[ "${1:-}" == "--sanitize" ]]; then
  if rustup toolchain list | grep -q nightly; then
    RUSTFLAGS="-Zsanitizer=address" ASAN_OPTIONS=detect_leaks=0 \
      cargo +nightly test -Zbuild-std --target "$(rustc -vV | sed -n 's/host: //p')" -p recovery-core -p recovery-ffi --all-features 2>&1 | tail -20
  else
    echo "nightly toolchain not installed; skipping AddressSanitizer run" >&2
    exit 2
  fi
fi
if [[ -d app && -x "$(command -v swift)" ]]; then
  cargo build --release -p recovery-ffi
  (cd app && swift build)
  scripts/swift-test.sh
fi
echo "all checks passed"
