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
trap 'rm -rf "$SCRATCH"' EXIT
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

if [[ -e "$OUTPUT" || -L "$OUTPUT" ]]; then
  echo "refusing to replace existing output: $OUTPUT" >&2
  exit 1
fi
mv "$STAGED_FRAMEWORK" "$OUTPUT"
echo "Built $OUTPUT"
