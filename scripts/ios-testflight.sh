#!/usr/bin/env bash
# Build and export the Symaira Vault iOS app for personal TestFlight testing.
#
# The preflight command is safe to run before Apple account setup. The archive
# and upload commands accept an App Store Connect API key through environment
# variables; SymVault can inject those variables without exposing their values.
#
# Usage:
#   scripts/ios-testflight.sh preflight
#   symvault run --env TEAM_ID=apple-developer/team-id.password \
#     --env ASC_API_KEY=apple-developer/notary-api-key.password \
#     --env ASC_KEY_ID=apple-developer/notary-api-key-id.password \
#     --env ASC_ISSUER_ID=apple-developer/notary-api-issuer-id.password -- \
#     scripts/ios-testflight.sh archive
#   scripts/ios-testflight.sh export
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLIENT_DIR="$REPO_ROOT/client"
PROJECT="$CLIENT_DIR/Symvault.xcodeproj"
SCHEME="SymvaultIOSApp"
ARCHIVE_PATH="${ARCHIVE_PATH:-$CLIENT_DIR/.build/testflight/SymvaultIOSApp.xcarchive}"
BUILD_PATH="${BUILD_PATH:-$CLIENT_DIR/.build/testflight/derived-data}"
EXPORT_PATH="${EXPORT_PATH:-$CLIENT_DIR/.build/testflight/export}"
EXPORT_OPTIONS="$CLIENT_DIR/ExportOptions-TestFlight.plist"
UPLOAD_OPTIONS="$CLIENT_DIR/ExportOptions-TestFlight-Upload.plist"
AUTH_ARGS=()
AUTH_KEY_FILE=""

if [[ -z "${DEVELOPER_DIR:-}" ]]; then
  for candidate in /Applications/Xcode-*.app /Applications/Xcode.app; do
    [[ -d "$candidate/Contents/Developer" ]] || continue
    [[ "$candidate" == *-beta.app ]] && continue
    export DEVELOPER_DIR="$candidate/Contents/Developer"
    break
  done
  if [[ -z "${DEVELOPER_DIR:-}" && -d /Applications/Xcode-beta.app/Contents/Developer ]]; then
    export DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer
  fi
fi

cleanup_auth() {
  [[ -z "$AUTH_KEY_FILE" ]] || rm -f "$AUTH_KEY_FILE"
}
trap cleanup_auth EXIT

prepare_auth() {
  AUTH_ARGS=(-allowProvisioningUpdates)
  [[ -z "${ASC_API_KEY:-}" ]] && return
  : "${ASC_KEY_ID:?ASC_KEY_ID is required with ASC_API_KEY}"
  : "${ASC_ISSUER_ID:?ASC_ISSUER_ID is required with ASC_API_KEY}"
  AUTH_KEY_FILE="$(mktemp "${TMPDIR:-/tmp}/symvault-asc-key.XXXXXX")"
  chmod 600 "$AUTH_KEY_FILE"
  if printf '%s' "$ASC_API_KEY" | base64 --decode >"$AUTH_KEY_FILE" 2>/dev/null && /usr/bin/grep -q -- 'BEGIN PRIVATE KEY' "$AUTH_KEY_FILE"; then
    :
  else
    printf '%s' "$ASC_API_KEY" >"$AUTH_KEY_FILE"
  fi
  AUTH_ARGS+=(
    -authenticationKeyPath "$AUTH_KEY_FILE"
    -authenticationKeyID "$ASC_KEY_ID"
    -authenticationKeyIssuerID "$ASC_ISSUER_ID"
  )
}

usage() {
  printf '%s\n' \
    "Usage: $0 {preflight|archive|export|upload}" \
    "  preflight  generate Vaultcore/project and build an unsigned iPhone app" \
    "  archive    build a signed archive with Xcode automatic signing" \
    "  export     export the signed archive as an App Store IPA" \
    "  upload     export and upload the archive to App Store Connect"
}

require_tools() {
  command -v xcodegen >/dev/null 2>&1 || {
    printf '%s\n' 'error: xcodegen is required' >&2
    exit 1
  }
  [[ -x "$DEVELOPER_DIR/usr/bin/xcodebuild" ]] || {
    printf '%s\n' "error: full Xcode not found at $DEVELOPER_DIR" >&2
    exit 1
  }
  [[ -d "$DEVELOPER_DIR/Platforms/iPhoneOS.platform" ]] || {
    printf '%s\n' 'error: iPhoneOS platform is missing from the selected Xcode' >&2
    exit 1
  }
}

prepare_project() {
  "$REPO_ROOT/scripts/build-vaultcore.sh"
  (
    cd "$CLIENT_DIR"
    xcodegen generate
  )
  xcodebuild -project "$PROJECT" -resolvePackageDependencies
}

preflight() {
  require_tools
  prepare_project
  rm -rf "$BUILD_PATH"
  mkdir -p "$BUILD_PATH"
  xcodebuild \
    -project "$PROJECT" \
    -scheme "$SCHEME" \
    -configuration Release \
    -sdk iphoneos \
    -destination 'generic/platform=iOS' \
    -derivedDataPath "$BUILD_PATH" \
    CODE_SIGNING_ALLOWED=NO \
    CODE_SIGNING_REQUIRED=NO \
    build
  APP_PATH="$BUILD_PATH/Build/Products/Release-iphoneos/Symaira Vault.app"
  [[ -d "$APP_PATH" ]] || {
    printf '%s\n' "error: expected iPhone app not found at $APP_PATH" >&2
    exit 1
  }
  APP_INFO="$APP_PATH/Info.plist"
  BUNDLE_ID=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$APP_INFO" 2>/dev/null)
  [[ "$BUNDLE_ID" == 'com.symaira.vault.ios' ]] || {
    printf '%s\n' "error: unexpected bundle ID: $BUNDLE_ID" >&2
    exit 1
  }
  APP_EXECUTABLE=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$APP_INFO" 2>/dev/null)
  [[ -x "$APP_PATH/$APP_EXECUTABLE" ]] || {
    printf '%s\n' "error: app executable missing: $APP_EXECUTABLE" >&2
    exit 1
  }
  printf '%s\n' "Unsigned iPhone app ready: $APP_PATH"
  printf '%s\n' 'Next: run archive with Team ID and ASC credentials injected from SymVault.'
}

archive() {
  require_tools
  [[ -n "${TEAM_ID:-}" ]] || {
    printf '%s\n' 'error: TEAM_ID is required; inject it from SymVault' >&2
    exit 1
  }
  prepare_project
  prepare_auth
  rm -rf "$ARCHIVE_PATH"
  mkdir -p "$(dirname "$ARCHIVE_PATH")"
  xcodebuild \
    -project "$PROJECT" \
    -scheme "$SCHEME" \
    -configuration Release \
    -sdk iphoneos \
    -destination 'generic/platform=iOS' \
    -archivePath "$ARCHIVE_PATH" \
    "${AUTH_ARGS[@]}" \
    DEVELOPMENT_TEAM="$TEAM_ID" \
    CODE_SIGN_STYLE=Automatic \
    CODE_SIGNING_ALLOWED=YES \
    CODE_SIGNING_REQUIRED=YES \
    archive
  [[ -d "$ARCHIVE_PATH/Products/Applications/Symaira Vault.app" ]] || {
    printf '%s\n' "error: signed archive contains no Symaira Vault.app" >&2
    exit 1
  }
  printf '%s\n' "Signed iPhone archive ready: $ARCHIVE_PATH"
}

export_archive() {
  [[ -d "$ARCHIVE_PATH" ]] || {
    printf '%s\n' "error: archive not found at $ARCHIVE_PATH; run archive first" >&2
    exit 1
  }
  [[ -d "$ARCHIVE_PATH/Products/Applications/Symaira Vault.app" ]] || {
    printf '%s\n' "error: archive contains no Symaira Vault.app; do not export it" >&2
    exit 1
  }
  prepare_auth
  rm -rf "$EXPORT_PATH"
  mkdir -p "$EXPORT_PATH"
  xcodebuild \
    -exportArchive \
    -archivePath "$ARCHIVE_PATH" \
    -exportPath "$EXPORT_PATH" \
    -exportOptionsPlist "$EXPORT_OPTIONS" \
    "${AUTH_ARGS[@]}"
  printf '%s\n' "TestFlight IPA exported under: $EXPORT_PATH"
}

upload_archive() {
  [[ -d "$ARCHIVE_PATH" ]] || {
    printf '%s\n' "error: archive not found at $ARCHIVE_PATH; run archive first" >&2
    exit 1
  }
  [[ -d "$ARCHIVE_PATH/Products/Applications/Symaira Vault.app" ]] || {
    printf '%s\n' "error: archive contains no Symaira Vault.app; do not upload it" >&2
    exit 1
  }
  prepare_auth
  xcodebuild \
    -exportArchive \
    -archivePath "$ARCHIVE_PATH" \
    -exportOptionsPlist "$UPLOAD_OPTIONS" \
    "${AUTH_ARGS[@]}"
  printf '%s\n' 'TestFlight upload submitted to App Store Connect.'
}

case "${1:-}" in
  preflight) preflight ;;
  archive) archive ;;
  export) export_archive ;;
  upload) upload_archive ;;
  *) usage >&2; exit 2 ;;
esac
