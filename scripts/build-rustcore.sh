#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 2 || $1 != --output ]]; then
  echo "Usage: $0 --output /path/to/SymvaultRustCore.xcframework" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
OUTPUT_PARENT="$(dirname "$2")"
OUTPUT_NAME="$(basename "$2")"
[[ "$OUTPUT_NAME" != . && "$OUTPUT_NAME" != / ]] || {
  echo "output must name an XCFramework path" >&2
  exit 2
}
mkdir -p "$OUTPUT_PARENT"
OUTPUT_PARENT="$(cd "$OUTPUT_PARENT" && pwd -P)"
OUTPUT="$OUTPUT_PARENT/$OUTPUT_NAME"

if [[ -e "$OUTPUT" || -L "$OUTPUT" ]]; then
  echo "refusing to replace existing output: $OUTPUT" >&2
  exit 1
fi

for sdk in iphoneos iphonesimulator; do
  xcrun --sdk "$sdk" --show-sdk-path >/dev/null
done

for target in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
  if ! rustup target list --installed | grep -Fxq "$target"; then
    echo "missing Rust target $target; install with: rustup target add $target" >&2
    exit 1
  fi
done

SCRATCH="$(mktemp -d "$OUTPUT_PARENT/.symvault-rustcore-build.XXXXXX")"
SIMULATOR_TO_SHUTDOWN=""
cleanup() {
  if [[ -n "$SIMULATOR_TO_SHUTDOWN" ]]; then
    xcrun simctl shutdown "$SIMULATOR_TO_SHUTDOWN" >/dev/null 2>&1 || true
  fi
  rm -rf "$SCRATCH"
}
trap cleanup EXIT
DEVICE_TARGET="aarch64-apple-ios"
SIM_ARM_TARGET="aarch64-apple-ios-sim"
SIM_X86_TARGET="x86_64-apple-ios"

build_target() {
  local target="$1"
  CARGO_TARGET_DIR="$SCRATCH/cargo-target" \
    cargo build --locked --release --package symvault-ffi --target "$target"
}

cd "$ROOT"
build_target "$DEVICE_TARGET"
build_target "$SIM_ARM_TARGET"
build_target "$SIM_X86_TARGET"

DEVICE_LIB="$SCRATCH/cargo-target/$DEVICE_TARGET/release/libsymvault_ffi.a"
SIM_ARM_LIB="$SCRATCH/cargo-target/$SIM_ARM_TARGET/release/libsymvault_ffi.a"
SIM_X86_LIB="$SCRATCH/cargo-target/$SIM_X86_TARGET/release/libsymvault_ffi.a"
SIM_UNIVERSAL_LIB="$SCRATCH/libsymvault_ffi-simulator.a"
lipo -create "$SIM_ARM_LIB" "$SIM_X86_LIB" -output "$SIM_UNIVERSAL_LIB"

STAGED_FRAMEWORK="$SCRATCH/SymvaultRustCore.xcframework"
xcodebuild -create-xcframework \
  -library "$DEVICE_LIB" -headers "$ROOT/crates/symvault-ffi/include" \
  -library "$SIM_UNIVERSAL_LIB" -headers "$ROOT/crates/symvault-ffi/include" \
  -output "$STAGED_FRAMEWORK"

for variant in "$STAGED_FRAMEWORK"/ios-*; do
  [[ -d "$variant" ]] || continue
  [[ -f "$variant/Headers/symvault_ffi.h" ]] || {
    echo "XCFramework is missing symvault_ffi.h: $variant" >&2
    exit 1
  }
  mkdir -p "$variant/Modules"
  cp "$ROOT/crates/symvault-ffi/include/module.modulemap" \
    "$variant/Modules/module.modulemap"
done

swift_smoke() {
  local sdk="$1" target="$2" variant="$3" library="$4"
  xcrun --sdk "$sdk" swiftc \
    -target "$target" -sdk "$(xcrun --sdk "$sdk" --show-sdk-path)" \
    -I "$STAGED_FRAMEWORK/$variant/Headers" \
    "$ROOT/crates/symvault-ffi/tests/ios_smoke.swift" \
    "$STAGED_FRAMEWORK/$variant/$library" \
    -framework Security -framework CoreFoundation \
    -framework UIKit \
    -o "$SCRATCH/smoke-$target"
}
swift_smoke iphoneos arm64-apple-ios17.0 ios-arm64 libsymvault_ffi.a
swift_smoke iphonesimulator arm64-apple-ios17.0-simulator ios-arm64_x86_64-simulator libsymvault_ffi-simulator.a
swift_smoke iphonesimulator x86_64-apple-ios17.0-simulator ios-arm64_x86_64-simulator libsymvault_ffi-simulator.a

if [[ "${SYMVAULT_RUN_IOS_SIMULATOR_SMOKE:-0}" == "1" ]]; then
  HOST_ARCH="$(uname -m)"
  case "$HOST_ARCH" in
    arm64) SIMULATOR_BINARY="$SCRATCH/smoke-arm64-apple-ios17.0-simulator" ;;
    x86_64) SIMULATOR_BINARY="$SCRATCH/smoke-x86_64-apple-ios17.0-simulator" ;;
    *) echo "unsupported simulator host architecture: $HOST_ARCH" >&2; exit 1 ;;
  esac

  SIMULATOR_UDID="${SYMVAULT_IOS_SIMULATOR_UDID:-}"
  if [[ -z "$SIMULATOR_UDID" ]]; then
    SIMULATOR_UDID="$(xcrun simctl list devices available -j | python3 -c '
import json, sys
devices = json.load(sys.stdin)["devices"]
print(next(device["udid"] for runtime, items in devices.items()
           if runtime.startswith("com.apple.CoreSimulator.SimRuntime.iOS")
           for device in items if device["isAvailable"] and device["name"].startswith("iPhone")))
')"
  fi
  if ! xcrun simctl list devices | grep -F "$SIMULATOR_UDID) (Booted)" >/dev/null; then
    xcrun simctl boot "$SIMULATOR_UDID"
    SIMULATOR_TO_SHUTDOWN="$SIMULATOR_UDID"
  fi
  xcrun simctl bootstatus "$SIMULATOR_UDID" -b

  SMOKE_BUNDLE_ID="com.symaira.rustcore.ios-smoke"
  SMOKE_APP="$SCRATCH/RustCoreSmoke.app"
  mkdir -p "$SMOKE_APP"
  cp "$SIMULATOR_BINARY" "$SMOKE_APP/RustCoreSmoke"
  mkdir -p "$SMOKE_APP/Fixtures"
  cp "$ROOT/testdata/port/crypto/age-kdf.json" "$SMOKE_APP/Fixtures/age-kdf.json"
  cp "$ROOT/testdata/port/store/store.json" "$SMOKE_APP/Fixtures/store.json"
  cp "$ROOT/crates/symvault-ffi/tests/fixtures/go-mobile-vault.json" "$SMOKE_APP/Fixtures/go-mobile-vault.json"
  chmod 755 "$SMOKE_APP/RustCoreSmoke"
  cat > "$SMOKE_APP/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleExecutable</key><string>RustCoreSmoke</string>
  <key>CFBundleIdentifier</key><string>com.symaira.rustcore.ios-smoke</string>
  <key>CFBundleName</key><string>RustCoreSmoke</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>LSRequiresIPhoneOS</key><true/>
  <key>MinimumOSVersion</key><string>17.0</string>
  <key>UIDeviceFamily</key><array><integer>1</integer><integer>2</integer></array>
  <key>CFBundleSupportedPlatforms</key><array><string>iPhoneSimulator</string></array>
</dict></plist>
PLIST
  codesign --force --sign - --timestamp=none "$SMOKE_APP"
  xcrun simctl install "$SIMULATOR_UDID" "$SMOKE_APP"
  SMOKE_DATA="$(xcrun simctl get_app_container "$SIMULATOR_UDID" "$SMOKE_BUNDLE_ID" data)"
  SMOKE_MARKER="$SMOKE_DATA/Documents/rust-ffi-smoke.pass"
  rm -f "$SMOKE_MARKER"
  xcrun simctl launch --terminate-running-process "$SIMULATOR_UDID" "$SMOKE_BUNDLE_ID"
  for _ in {1..60}; do
    if [[ -f "$SMOKE_MARKER" ]]; then break; fi
    sleep 1
  done
  [[ -f "$SMOKE_MARKER" ]] || { echo "iOS simulator FFI smoke did not complete" >&2; exit 1; }
  [[ "$(cat "$SMOKE_MARKER")" == "go-fixture-contracts-ok" ]] || {
    echo "iOS simulator FFI smoke returned unexpected result" >&2
    exit 1
  }
  echo "PASS iOS simulator Go-fixture Rust FFI contracts ($HOST_ARCH)"
fi

if [[ -e "$OUTPUT" || -L "$OUTPUT" ]]; then
  echo "refusing to replace existing output: $OUTPUT" >&2
  exit 1
fi
mv "$STAGED_FRAMEWORK" "$OUTPUT"
echo "Built $OUTPUT"
