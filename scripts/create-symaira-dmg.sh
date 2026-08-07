#!/bin/bash
set -euo pipefail

usage() {
  echo "Usage: $0 <app-path> <dmg-path> [volume-name] [background-png]" >&2
}

if [ "$#" -lt 2 ] || [ "$#" -gt 4 ]; then
  usage
  exit 2
fi

APP_PATH="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
DMG_PATH="$2"
VOL_NAME="${3:-$(basename "$APP_PATH" .app)}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_BACKGROUND="${SCRIPT_DIR}/../Brand/DMG/symaira-dmg-background.png"
if [ ! -f "$DEFAULT_BACKGROUND" ]; then
  DEFAULT_BACKGROUND="${SCRIPT_DIR}/../assets/branding/symaira-dmg-background.png"
fi
BACKGROUND_PATH="${4:-$DEFAULT_BACKGROUND}"

if [ ! -d "$APP_PATH" ]; then
  echo "error: app bundle not found: $APP_PATH" >&2
  exit 1
fi
if [ ! -f "$BACKGROUND_PATH" ]; then
  echo "error: DMG background not found: $BACKGROUND_PATH" >&2
  exit 1
fi

OUTPUT_DIR="$(dirname "$DMG_PATH")"
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"
DMG_PATH="$OUTPUT_DIR/$(basename "$DMG_PATH")"

WORK_DIR="$(mktemp -d)"
STAGE_DIR="$WORK_DIR/stage"
RW_DMG="$WORK_DIR/installer-rw.dmg"
MOUNT_DIR=""
DEVICE=""

cleanup() {
  if [ -n "$DEVICE" ]; then
    hdiutil detach "$DEVICE" -quiet 2>/dev/null || true
  fi
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

mkdir -p "$STAGE_DIR/.background"
cp -R "$APP_PATH" "$STAGE_DIR/"
ln -s /Applications "$STAGE_DIR/Applications"
cp "$BACKGROUND_PATH" "$STAGE_DIR/.background/symaira-dmg-background.png"

hdiutil create \
  -quiet \
  -fs HFS+ \
  -format UDRW \
  -volname "$VOL_NAME" \
  -srcfolder "$STAGE_DIR" \
  "$RW_DMG"

ATTACH_OUTPUT="$(hdiutil attach -readwrite -noverify -noautoopen "$RW_DMG")"
DEVICE="$(printf '%s\n' "$ATTACH_OUTPUT" | awk '/^\/dev\// {print $1; exit}')"
MOUNT_DIR="$(printf '%s\n' "$ATTACH_OUTPUT" | awk -F '\t' '/^\/dev\// && $3 ~ /^\/Volumes\// {print $3; exit}')"
if [ -z "$DEVICE" ] || [ -z "$MOUNT_DIR" ]; then
  echo "error: could not determine mounted DMG device or volume path" >&2
  exit 1
fi

APP_FILE="$(basename "$APP_PATH")"
MOUNT_NAME="$(basename "$MOUNT_DIR")"
osascript <<APPLESCRIPT
tell application "Finder"
  tell disk "${MOUNT_NAME}"
    open
    set current view of container window to icon view
    set toolbar visible of container window to false
    set statusbar visible of container window to false
    set pathbar visible of container window to false
    set bounds of container window to {120, 120, 780, 540}
    set theViewOptions to the icon view options of container window
    set arrangement of theViewOptions to not arranged
    set icon size of theViewOptions to 112
    set text size of theViewOptions to 13
    set background picture of theViewOptions to file ".background:symaira-dmg-background.png"
    set position of item "${APP_FILE}" of container window to {180, 220}
    set position of item "Applications" of container window to {480, 220}
    update without registering applications
    delay 1
    close
  end tell
end tell
APPLESCRIPT

sync
hdiutil detach "$DEVICE" -quiet
DEVICE=""

rm -f "$DMG_PATH"
hdiutil convert -quiet "$RW_DMG" -format UDZO -imagekey zlib-level=9 -o "$DMG_PATH"
echo "Created $DMG_PATH"
