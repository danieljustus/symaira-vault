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
  verify_hash ff2e1aeef59d2f012a620a1a4042e78dc31a179b2d16b33c5cc4277f0b5b03ca client/AppIcon.icon/icon.json
  verify_hash 28a132532faa49ac66c896b0df4d304e6e19de9d42da85398f001a50178da50e client/AppIcon.icon/Assets/S.png
  verify_hash a028c00a8a9b14130fb860e0b458be34291b650311812e50db1a5a090e9faf4e client/AppIcon.icon/Assets/signet.png
  verify_hash 6076d7799a91a1f465f3640d2c35bcc1abee43dff8bc270268b4492205512eb9 assets/branding/symaira-vault.icns

  local mac_hashes=(
    "9983e1aee04e87e5acb79e9987fc879b75038a1ebbbcc00f968d5231e862e94a icon_128x128.png"
    "5f2163ddfd805f53c1e1ad6801244e292db1c458253989ee3ed50131de20ae9d icon_128x128@2x.png"
    "263881d0f7516b1b6c44c8b4eb98b8250ff590089eea7470dc692cb1d2991f29 icon_16x16.png"
    "85895923c6770a4ecf6a8b2e2f9eae5840bd059380180c1ecdfc47931b190ea1 icon_16x16@2x.png"
    "5f2163ddfd805f53c1e1ad6801244e292db1c458253989ee3ed50131de20ae9d icon_256x256.png"
    "b1e64e86108c92c3335a3c429ffecadd4fab2f24c2965ded223ba62b80b196e9 icon_256x256@2x.png"
    "85895923c6770a4ecf6a8b2e2f9eae5840bd059380180c1ecdfc47931b190ea1 icon_32x32.png"
    "3e2c717d8edfb5828aa6dcf407d3efd493c3700796e951e1479838b68e8d4ea7 icon_32x32@2x.png"
    "b1e64e86108c92c3335a3c429ffecadd4fab2f24c2965ded223ba62b80b196e9 icon_512x512.png"
    "288ea315c9299aaff6b646433678fb353342d570dcd75d236aed996add1e566a icon_512x512@2x.png"
  )
  for entry in "${mac_hashes[@]}"; do
    verify_hash "${entry%% *}" "client/Sources/SymvaultApp/Assets.xcassets/LegacyMacAppIcon.appiconset/${entry#* }"
  done

  local ios_hashes=(
    "05cf1f375feb4cde69863a313992420af72dd4455a68298ea83ec1477b27de61 icon-1024.png"
    "1a728804a38d0c758a7824fdc6d9fb854de3658918897186fc257a22d9c3041c icon-20@1x.png"
    "64d92219f03485c03831cf2ad6eaac048e67891fe1a894374082ab46b2bc4ed4 icon-20@2x.png"
    "25bb8bfcef22d516640aa893e4dacc6a5aef66009a3c876254126f6cbe6ba980 icon-20@3x.png"
    "6e5e16f4d2e2538830096746f40a4d6e835b5aad03cae9ffbf19b0242d7274df icon-29@1x.png"
    "4de843512ded0cb379ccf1e1c068445f44b0c335205ebff8290f36cfcd431ae5 icon-29@2x.png"
    "1b844812f05df65121682300da3e67b74fe052edeca4d8f7e321deb984d5239e icon-29@3x.png"
    "64d92219f03485c03831cf2ad6eaac048e67891fe1a894374082ab46b2bc4ed4 icon-40@1x.png"
    "0341d1dc39814e5fb0e418d4e62802b2ec8a16bfa2fe8bdec60734b3444abbe5 icon-40@2x.png"
    "b1d7189db5121a89afb958e411e05c4c280fd4f991bd6a9fe63964425b64f988 icon-40@3x.png"
    "b1d7189db5121a89afb958e411e05c4c280fd4f991bd6a9fe63964425b64f988 icon-60@2x.png"
    "036f6a8e518c27a45afd06abe47a4c85932ba650728e111af27111d3903e8274 icon-60@3x.png"
    "37f14b5a661aeec0d90edbd1832ab1cdea036dbc110bb912c221d4c5bca30cbe icon-76@1x.png"
    "126ec736726cedf7d05311284293c374d58dd9de4b15d9363a16a6068986a595 icon-76@2x.png"
    "c2eb88245f150f9888d0347e988dac2c15ba0a1722d25ef90eecc0dcb23af4f9 icon-83.5@2x.png"
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
