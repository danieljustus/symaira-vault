#!/usr/bin/env bash
# FFI-001: package crates/symvault-ffi as SymvaultFFI.xcframework.
#
# Builds libsymvault_ffi.a with the `ffi` Cargo profile (release + panic=unwind,
# see ADR 0031) for three slices
#
#   aarch64-apple-darwin     macOS arm64
#   aarch64-apple-ios        iOS device arm64
#   aarch64-apple-ios-sim    iOS Simulator arm64
#
# and joins them with `xcodebuild -create-xcframework`, each slice carrying the
# C header and a `CSymvaultFFI` module map (so `import CSymvaultFFI` in the Swift
# wrapper resolves against the framework).
#
# Everything lands below $CARGO_TARGET_DIR (default: <repo>/target, which is
# git-ignored); nothing is written into the tracked tree. Override the output
# directory with SYMVAULT_XCFRAMEWORK_OUT. Tool launchers are overridable:
#   CARGO="dev-external cargo" scripts/rust-port/build-ffi-xcframework.sh
# xcodebuild is deliberately not wrapped (XCFRAMEWORK_XCODEBUILD, default
# `xcodebuild`): dev-external appends -derivedDataPath, which
# `xcodebuild -create-xcframework` rejects (it only joins prebuilt libraries).
#
# Prints one `SIZE` line per slice and a `TOTAL` line (bytes), for ADR 0031.
set -euo pipefail

if [ "$(uname -s)" != "Darwin" ]; then
  echo "build-ffi-xcframework: needs macOS (xcodebuild -create-xcframework); host: $(uname -s)" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

cargo_cmd="${CARGO:-cargo}"
xcodebuild_cmd="${XCFRAMEWORK_XCODEBUILD:-xcodebuild}"
target_dir="${CARGO_TARGET_DIR:-target}"
case "$target_dir" in /*) ;; *) target_dir="$repo_root/$target_dir" ;; esac
out_dir="${SYMVAULT_XCFRAMEWORK_OUT:-$target_dir/xcframework}"
case "$out_dir" in /*) ;; *) out_dir="$repo_root/$out_dir" ;; esac

# Never write into the checkout except the git-ignored default target/.
case "$out_dir/" in
  "$repo_root/target/"*) ;;
  "$repo_root/"*)
    echo "build-ffi-xcframework: refusing to write inside the repository: $out_dir" >&2
    exit 2
    ;;
esac

header_src="crates/symvault-ffi/swift/Sources/CSymvaultFFI/include/symvault_ffi.h"
[ -f "$header_src" ] || { echo "missing header: $header_src" >&2; exit 2; }

triples=(aarch64-apple-darwin aarch64-apple-ios aarch64-apple-ios-sim)
framework="$out_dir/SymvaultFFI.xcframework"
headers="$out_dir/headers"
slices="$out_dir/slices"

# 1. one staticlib per slice (ffi profile; the pinned toolchain must have the
#    targets: `rustup target add aarch64-apple-ios aarch64-apple-ios-sim`).
for triple in "${triples[@]}"; do
  echo "== build $triple"
  # shellcheck disable=SC2086
  CARGO_TARGET_DIR="$target_dir" $cargo_cmd build -p symvault-ffi --profile ffi --locked --target "$triple"
done

# 2. header dir shared by all slices.
rm -rf "$out_dir/headers" "$slices" "$framework"
mkdir -p "$headers" "$slices"
cp "$header_src" "$headers/symvault_ffi.h"
cat > "$headers/module.modulemap" <<'EOF'
module CSymvaultFFI {
    header "symvault_ffi.h"
    export *
}
EOF

# 3. XCFramework.
args=()
for triple in "${triples[@]}"; do
  lib="$target_dir/$triple/ffi/libsymvault_ffi.a"
  [ -s "$lib" ] || { echo "missing staticlib: $lib" >&2; exit 1; }
  mkdir -p "$slices/$triple"
  cp "$lib" "$slices/$triple/libsymvault_ffi.a"
  args+=(-library "$slices/$triple/libsymvault_ffi.a" -headers "$headers")
done
echo "== create $framework"
# shellcheck disable=SC2086
$xcodebuild_cmd -create-xcframework "${args[@]}" -output "$framework"

# 4. verify three slices and report sizes.
plist="$framework/Info.plist"
count="$(/usr/libexec/PlistBuddy -c 'Print :AvailableLibraries' "$plist" | grep -c 'LibraryIdentifier')"
if [ "$count" != "3" ]; then
  echo "expected 3 slices in $plist, found $count" >&2
  exit 1
fi

total=0
echo "== slices ($plist)"
for dir in "$framework"/*/; do
  id="$(basename "$dir")"
  lib="$dir/libsymvault_ffi.a"
  [ -f "$lib" ] || { echo "slice $id has no libsymvault_ffi.a" >&2; exit 1; }
  [ -f "$dir/Headers/symvault_ffi.h" ] || { echo "slice $id has no header" >&2; exit 1; }
  size="$(stat -f %z "$lib")"
  total=$((total + size))
  printf 'SIZE %-28s %12d bytes\n' "$id" "$size"
done
printf 'TOTAL %-27s %12d bytes (sum of the %s libsymvault_ffi.a slices)\n' SymvaultFFI.xcframework "$total" "$count"
du -sk "$framework" | awk '{ printf "DISK  SymvaultFFI.xcframework        %12d KiB on disk (du -sk)\n", $1 }'

# 5. What an app actually pays: the .a above is a build input carrying every
#    object of the dependency tree. Link a stub executable that keeps all
#    exported symbols (-u) with -dead_strip per slice and report its size (the
#    stub itself is a few KiB).
linkdir="$out_dir/linksize"
rm -rf "$linkdir"
mkdir -p "$linkdir"
printf '#include "symvault_ffi.h"\nint main(void) { return (int)symvault_ffi_abi_version(); }\n' > "$linkdir/main.c"
keep=()
while IFS= read -r sym; do keep+=("-Wl,-u,_$sym"); done \
  < <(grep -oE 'symvault_[a-z0-9_]+\(' "$header_src" | tr -d '(' | sort -u)
link_slice() { # <slice id> <target triple> <sdk>
  local id="$1" tgt="$2" sdk="$3" exe
  exe="$linkdir/link-$id"
  xcrun clang -O2 -I "$headers" -target "$tgt" -isysroot "$(xcrun --sdk "$sdk" --show-sdk-path)" \
    "$linkdir/main.c" "$framework/$id/libsymvault_ffi.a" -liconv -Wl,-dead_strip "${keep[@]}" -o "$exe"
  printf 'LINKED %-27s %12d bytes (%s, %d exports kept, -dead_strip; %s)\n' \
    "$id" "$(stat -f %z "$exe")" "$tgt" "${#keep[@]}" \
    "$(xcrun vtool -show-build "$exe" | awk '/platform/ { print $2 }')"
}
link_slice macos-arm64 arm64-apple-macos13 macosx
link_slice ios-arm64 arm64-apple-ios16.0 iphoneos
link_slice ios-arm64-simulator arm64-apple-ios16.0-simulator iphonesimulator
echo "xcframework: $framework"
