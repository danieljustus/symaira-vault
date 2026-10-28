#!/bin/bash
set -euo pipefail

# Validate the approved Icon Composer source, legacy fallbacks, and compiled app.
# Keep the hashes pinned so a stale or silently substituted glyph fails closed.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

sha256() {
  shasum -a 256 "$1" | awk '{print $1}'
}

verify_hash() {
  local expected="$1" path="$2" actual
  [ -f "$REPO_ROOT/$path" ] || fail "missing approved icon file: $path"
  actual="$(sha256 "$REPO_ROOT/$path")"
  [ "$actual" = "$expected" ] || fail "icon drift detected: $path"
}

verify_dimensions() {
  local path="$1" width="$2" height="$3" actual_width actual_height
  [ -f "$REPO_ROOT/$path" ] || fail "missing legacy icon file: $path"
  actual_width="$(sips -g pixelWidth "$REPO_ROOT/$path" 2>/dev/null | awk '/pixelWidth:/ {print $2}')"
  actual_height="$(sips -g pixelHeight "$REPO_ROOT/$path" 2>/dev/null | awk '/pixelHeight:/ {print $2}')"
  [ "$actual_width" = "$width" ] && [ "$actual_height" = "$height" ] || \
    fail "legacy icon has wrong dimensions: $path (${actual_width}x${actual_height}, expected ${width}x${height})"
}

verify_source() {
  verify_hash 64f3e52914a05e1159012df31d9d850d6ac622fadd248134d0ce5b5b2f232ebf client/AppIcon.icon/icon.json
  verify_hash 4c9382cb89daafbc5abe1daccf5c677cea32de251cd121dca14d3fdd40ff2458 client/AppIcon.icon/Assets/signet.png
  verify_hash 31acbee4bc3a714885bc0fc0394349f519c6326dad98e65fa7ade28bcd21d279 client/AppIcon.icon/Assets/top.png
  verify_hash 151c783d1962c20a5140218ddeb7ec92e6ed47a992534abd136dee1a56dabbd3 client/AppIcon.icon/Assets/bot.png
  verify_hash f6d54660cf5b3620c5084d9d1647f3c9844cbd207d8b948cf46950a14c3689dd client/AppIcon.icon/Assets/lines.png
  verify_hash c328039e79d2fd68f8f31ddbc8c7ed2aca5b6f9645bc5c15e1d9976f1683b675 client/AppIcon.icon/Assets/index.png
  verify_hash 4d17dedae2b112cc6a87ba43e942a048dbd96fd658bf16643dad3815fe4598e8 assets/branding/symaira-vault.icns

  local mac_hashes=(
    "628ef31dede35944887ead9ee62716b77314a2bcc62d955076ba04a6cf01d994 icon_128x128.png"
    "43112677c80b72694042577664a4f868b002bad365d838859a1e8c300cd9201e icon_128x128@2x.png"
    "e886bc6ab8cf10322eb2885bf6e85caebd7ea521ff1538d764d00bdb58edf0f3 icon_16x16.png"
    "ee7acf9ad6a499834afa6d7edca8d0b103bb2b587032933cb92ebbbcb5c97eee icon_16x16@2x.png"
    "43112677c80b72694042577664a4f868b002bad365d838859a1e8c300cd9201e icon_256x256.png"
    "6d7bd04c5a9e75494470c012beb73b1b27ca0b816848c6e3bcc06a8d2a627e63 icon_256x256@2x.png"
    "ee7acf9ad6a499834afa6d7edca8d0b103bb2b587032933cb92ebbbcb5c97eee icon_32x32.png"
    "621be52deab8cab4dd448ef5f3c59937b58346f3a1d896be816c9d3dc1969b80 icon_32x32@2x.png"
    "6d7bd04c5a9e75494470c012beb73b1b27ca0b816848c6e3bcc06a8d2a627e63 icon_512x512.png"
    "a8ed9248a7588073eddc301ecb75ac897dc4488fe8615ae60c13b5505381fc49 icon_512x512@2x.png"
  )
  for entry in "${mac_hashes[@]}"; do
    verify_hash "${entry%% *}" "client/Sources/SymvaultApp/Assets.xcassets/LegacyMacAppIcon.appiconset/${entry#* }"
  done

  local ios_hashes=(
    "76647508b90db716ce8897e4b162c3a0eb8bb112aeba6d975cea5f29d21f10b1 icon-1024.png"
    "3b6e5957d8824b5d296671fbdfd56fd33dec43eb422b312bbbbde93993711554 icon-20@1x.png"
    "3274bb0d896a6fa3c5a1f223672a8349b566b797ce80858a7bfb4a333de1422f icon-20@2x.png"
    "da267df7cf9e22451754075ab437c232a4c25c9236f6706f574f4a088bd762a7 icon-20@3x.png"
    "a578d493acdd0b658bd73f8dd946f589286b68da57c2a02eb11947116954d1f6 icon-29@1x.png"
    "666de27292fa0b19ae2e0be0440d8d0e18b00aefb96228d9ddf39a29973f5377 icon-29@2x.png"
    "50946ccbe3ecbd8397342a323f3648eb5c77319fa70d18c6a85d0e741f5d52de icon-29@3x.png"
    "3274bb0d896a6fa3c5a1f223672a8349b566b797ce80858a7bfb4a333de1422f icon-40@1x.png"
    "5d5925b53552f67f1acd26b2cea1e520cf5b04ec763b1989127b5a8693df7323 icon-40@2x.png"
    "fcb312e1a70b2ff03f3642a9bf4bafadb812e42bda5a3c33a27aa71a1092c589 icon-40@3x.png"
    "fcb312e1a70b2ff03f3642a9bf4bafadb812e42bda5a3c33a27aa71a1092c589 icon-60@2x.png"
    "b9582e954220bf9c59c544f45dfe40244f19e6db9b213079809dde0ed7b0a8b0 icon-60@3x.png"
    "a1daffae3d50cd1f1d7e91849d019c726e563eb5bdb2809072d15959164684c0 icon-76@1x.png"
    "f4b8e2a0e129a90ca140f36ed5c3ac2fea33ae2cee93d612b4aa9154fa5b5771 icon-76@2x.png"
    "0a2e09bd4f969cec82d66c64789c92bc0251394444edd6313b89924d7946e491 icon-83.5@2x.png"
  )
  for entry in "${ios_hashes[@]}"; do
    verify_hash "${entry%% *}" "client/Sources/SymvaultIOS/Assets.xcassets/LegacyIOSAppIcon.appiconset/${entry#* }"
  done

  for spec in \
    'icon-20@1x.png:20' 'icon-20@2x.png:40' 'icon-20@3x.png:60' \
    'icon-29@1x.png:29' 'icon-29@2x.png:58' 'icon-29@3x.png:87' \
    'icon-40@1x.png:40' 'icon-40@2x.png:80' 'icon-40@3x.png:120' \
    'icon-60@2x.png:120' 'icon-60@3x.png:180' 'icon-76@1x.png:76' \
    'icon-76@2x.png:152' 'icon-83.5@2x.png:167' 'icon-1024.png:1024'; do
    verify_dimensions "client/Sources/SymvaultIOS/Assets.xcassets/LegacyIOSAppIcon.appiconset/${spec%%:*}" "${spec##*:}" "${spec##*:}"
  done

  [ ! -d "$REPO_ROOT/client/Sources/SymvaultApp/Assets.xcassets/AppIcon.appiconset" ] || fail "legacy mac AppIcon.appiconset collides with AppIcon.icon"
  [ ! -d "$REPO_ROOT/client/Sources/SymvaultIOS/Assets.xcassets/AppIcon.appiconset" ] || fail "legacy iOS AppIcon.appiconset collides with AppIcon.icon"
  grep -q 'fileTypes:' "$REPO_ROOT/client/project.yml" || fail 'XcodeGen .icon file wrapper configuration is missing'
  [ "$(grep -c -- '- path: AppIcon.icon' "$REPO_ROOT/client/project.yml")" -eq 2 ] || fail 'AppIcon.icon is not wired to both app targets'
  grep -q 'scripts/verify-vault-icon.sh' "$REPO_ROOT/client/project.yml" || fail 'build-time icon guard is missing'
  grep -q 'scripts/verify-vault-icon.sh --bundle' "$REPO_ROOT/.github/workflows/release.yml" || fail 'release compiled-icon guard is missing'
  grep -q 'assets/branding/symaira-vault.icns' "$REPO_ROOT/.github/workflows/release.yml" || fail 'release DMG icon is missing'
  printf '%s\n' 'Approved Vault icon source and legacy fallbacks verified.'
}

verify_bundle() {
  local app="$1" plist assets info
  [ -d "$app" ] || fail "built app bundle missing: $app"
  if [ -d "$app/Contents" ]; then
    plist="$app/Contents/Info.plist"
    assets="$app/Contents/Resources/Assets.car"
  else
    plist="$app/Info.plist"
    assets="$app/Assets.car"
  fi
  [ -f "$plist" ] || fail "built app Info.plist missing: $plist"
  [ -f "$assets" ] || fail "compiled asset catalog missing: $assets"
  info=""
  for plist_key in \
    ':CFBundleIconName' \
    ':CFBundleIcons:CFBundlePrimaryIcon:CFBundleIconName' \
    ':CFBundleIcons~ipad:CFBundlePrimaryIcon:CFBundleIconName'; do
    info="$(/usr/libexec/PlistBuddy -c "Print $plist_key" "$plist" 2>/dev/null || true)"
    [ "$info" = 'AppIcon' ] && break
  done
  [ "$info" = 'AppIcon' ] || fail "built bundle does not select AppIcon (got: ${info:-missing})"
  assetutil --info "$assets" >"${TMPDIR:-/tmp}/symaira-vault-assets.$$.json" 2>/dev/null || fail "asset catalog inspection failed: $assets"
  grep -q 'AppIcon' "${TMPDIR:-/tmp}/symaira-vault-assets.$$.json" || fail "compiled asset catalog has no AppIcon rendition: $assets"
  rm -f "${TMPDIR:-/tmp}/symaira-vault-assets.$$.json"
  printf 'Compiled Vault icon verified in %s\n' "$app"
}

case "${1:---source-only}" in
  --source-only)
    verify_source
    ;;
  --bundle)
    [ "$#" -eq 2 ] || fail 'usage: verify-vault-icon.sh --bundle /path/to/App.app'
    verify_source
    verify_bundle "$2"
    ;;
  *)
    printf 'usage: %s [--source-only | --bundle /path/to/App.app]\n' "$0" >&2
    exit 2
    ;;
esac
