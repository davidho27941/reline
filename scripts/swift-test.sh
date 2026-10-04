#!/usr/bin/env bash
# Run the Swift test suite. With full Xcode, plain `swift test` works. With Command Line Tools
# only, XCTest is absent but Swift Testing ships as a framework; point the toolchain at it.
set -euo pipefail
cd "$(dirname "$0")/../app"
export PATH="$HOME/.cargo/bin:$PATH"
FW=/Library/Developer/CommandLineTools/Library/Developer/Frameworks
# Prefer a full Xcode when one is installed, even if xcode-select still points at the CLT.
if [[ -z "${DEVELOPER_DIR:-}" && -d /Applications/Xcode.app/Contents/Developer ]]; then
  export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
fi
if [[ -n "${DEVELOPER_DIR:-}" ]] || xcode-select -p 2>/dev/null | grep -q "Xcode.app"; then
  exec swift test
fi
exec swift test --disable-xctest --enable-swift-testing \
  -Xswiftc -F -Xswiftc "$FW" -Xlinker -F -Xlinker "$FW" -Xlinker -rpath -Xlinker "$FW"
