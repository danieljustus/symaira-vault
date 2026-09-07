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
  verify_hash a3251f55007fb2c4c1460d4dc79ab0ee346c30a3a5b30cfcd1fe9c0954e14b76 client/AppIcon.icon/icon.json
  verify_hash 28a132532faa49ac66c896b0df4d304e6e19de9d42da85398f001a50178da50e client/AppIcon.icon/Assets/S.png
  verify_hash a028c00a8a9b14130fb860e0b458be34291b650311812e50db1a5a090e9faf4e client/AppIcon.icon/Assets/signet.png
  verify_hash bbecf5fae1efce761d889f88bdc98e4b013fdad5bd46c981bd5710ff0e8da970 assets/branding/symaira-vault.icns

  local mac_hashes=(
    "16a7955fd92baca978afb01e731d65a712963d58a26902ddc4e1aaad4abfa54b icon_128x128.png"
    "19beba1b26da1ace4844a6176f90b4320f06be19ddf576499b019fd8d780c841 icon_128x128@2x.png"
    "0e9a825b71be015b15eb4b30ebfd4221200fcb850476a37b5d767360f14f093f icon_16x16.png"
    "22a826be8e8cdd68a539062833ecd2ce34c7a59c649e855f7c1c47cdd6f327af icon_16x16@2x.png"
    "19beba1b26da1ace4844a6176f90b4320f06be19ddf576499b019fd8d780c841 icon_256x256.png"
    "6340bc5355bac9ddcf58537f6c630e7e652deb3dc269a3e8f44b16015f799f9e icon_256x256@2x.png"
    "22a826be8e8cdd68a539062833ecd2ce34c7a59c649e855f7c1c47cdd6f327af icon_32x32.png"
    "1bb587cbdbdb9afeabdc86b520ea5cbacd9df5bd42944be4ef2f716d8b3fd748 icon_32x32@2x.png"
    "6340bc5355bac9ddcf58537f6c630e7e652deb3dc269a3e8f44b16015f799f9e icon_512x512.png"
    "663542a83961e166e3ec753cab848c0bd5df732a22d27bdd567199bdb7002904 icon_512x512@2x.png"
  )
  for entry in "${mac_hashes[@]}"; do
    verify_hash "${entry%% *}" "client/Sources/SymvaultApp/Assets.xcassets/LegacyMacAppIcon.appiconset/${entry#* }"
  done

  local ios_hashes=(
    "81cfd61f1e9039ef89123f9c283d380bf20a4d4616feb7e549a4986afddcfef6 icon-1024.png"
    "54aa639238c134a2b364aab38d94193035ebe69ea199bd6c62f19995e12ee420 icon-20@1x.png"
    "ab591995a84197e5eb3b6741da593a42aa1360093f5936119e29955c5f5dd144 icon-20@2x.png"
    "38b74724b205d75a0c3583e10468a84fceffd095e246ed062de4a42cfc82eef7 icon-20@3x.png"
    "28ed5ddde9457089ce11dcc2d9950911e839e89a145ab4d1bbde853527647074 icon-29@1x.png"
    "3519c46b4b8bf927a380d5078125a45d18c08957daf1a8c91aaae186ed9d758b icon-29@2x.png"
    "19138b3d7313bbc9e16dce3013d3c83fae597a5a5d7b79ed2a317a2b97562968 icon-29@3x.png"
    "ab591995a84197e5eb3b6741da593a42aa1360093f5936119e29955c5f5dd144 icon-40@1x.png"
    "6d2d0e254ff226a5805f471ce37823ad4bf05902cfc6425c401e25b9fa25c725 icon-40@2x.png"
    "1dd2a38caa19743200a50ebbe76aeb098ae2f6fbf1a37dc4498f5bfa1796d85e icon-40@3x.png"
    "1dd2a38caa19743200a50ebbe76aeb098ae2f6fbf1a37dc4498f5bfa1796d85e icon-60@2x.png"
    "556307e6bce01d14058574a44e5bf9c7d94005c9fa8472fa362a1b22605d86c2 icon-60@3x.png"
    "1513579d16cb8ada8e5b6b7f8b1f6c8779636c60fe16460dd9d9bb2e3dca9f90 icon-76@1x.png"
    "bf38001aae833789bbcc7c7464a1d72b85778359737d99bb8244474fffd334d0 icon-76@2x.png"
    "f8168bde46c4c7bf5567cb3e6c424a8dd58e21ec2633a2eda466305a7238f2f6 icon-83.5@2x.png"
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
