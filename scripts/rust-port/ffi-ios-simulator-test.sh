#!/usr/bin/env bash
# FFI-001: replay testdata/port/ffi/mobilebind.json through the Swift package on
# an iOS Simulator, linking the iOS-Simulator slice of SymvaultFFI.xcframework
# (build it first: `make ffi-xcframework`).
#
# Two steps, both independent of `xcodebuild test -destination`:
#   1. xcodebuild build-for-testing for `generic/platform=iOS Simulator`
#      (arm64) produces SymvaultFFITests.xctest;
#   2. simctl boots the device and `simctl spawn` runs the SDK's xctest agent on
#      that bundle inside the simulator.
# `xcodebuild test -destination id=<udid>` needs Xcode's CoreSimulator client to
# match the installed CoreSimulator; when it does not (Xcode: "CoreSimulator is
# out of date", scheme list empty) only the simctl route works.
#
# Environment:
#   CARGO_TARGET_DIR          where ffi-xcframework wrote its output (default <repo>/target)
#   SYMVAULT_XCFRAMEWORK_OUT  override of <target>/xcframework
#   XCODEBUILD                launcher for xcodebuild (default `xcodebuild`;
#                             `dev-external xcodebuild` also works)
#   SIMCTL                    simctl command (default `xcrun simctl`). Xcode's
#                             simctl wrapper runs `xcodebuild -runFirstLaunch`
#                             when CoreSimulator is older than the Xcode expects,
#                             and that can hang; the real binary
#                             /Library/Developer/PrivateFrameworks/CoreSimulator.framework/
#                             Versions/A/Resources/bin/simctl answers at once.
#   IOS_SIM_UDID              use this existing device instead of finding/creating one
#   IOS_SIM_NAME              name of the device this script owns (default symvault-ffi-ios)
#   IOS_SIM_DEVICETYPE        device type to create (default iPhone-16)
#   IOS_SIM_TIMEOUT           seconds for each simctl query (default 60)
#   IOS_SIM_TEST_TIMEOUT      seconds for build and for the test run (default 1800)
#
# The script creates at most one device (IOS_SIM_NAME), boots it if needed and
# shuts it down again only when it booted it. It never deletes or erases devices,
# never touches other devices and never restarts CoreSimulatorService.
set -euo pipefail

if [ "$(uname -s)" != "Darwin" ]; then
  echo "ffi-ios-simulator-test: needs macOS (host: $(uname -s))" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

xcodebuild_cmd="${XCODEBUILD:-xcodebuild}"
simctl_cmd="${SIMCTL:-xcrun simctl}"
target_dir="${CARGO_TARGET_DIR:-target}"
case "$target_dir" in /*) ;; *) target_dir="$repo_root/$target_dir" ;; esac
out_dir="${SYMVAULT_XCFRAMEWORK_OUT:-$target_dir/xcframework}"
case "$out_dir" in /*) ;; *) out_dir="$repo_root/$out_dir" ;; esac
framework="$out_dir/SymvaultFFI.xcframework"
work_dir="$target_dir/ffi-ios-sim"
name="${IOS_SIM_NAME:-symvault-ffi-ios}"
devicetype="com.apple.CoreSimulator.SimDeviceType.${IOS_SIM_DEVICETYPE:-iPhone-16}"
query_timeout="${IOS_SIM_TIMEOUT:-60}"
test_timeout="${IOS_SIM_TEST_TIMEOUT:-1800}"

[ -d "$framework/ios-arm64-simulator" ] || {
  echo "missing $framework (run: make ffi-xcframework)" >&2
  exit 2
}
mkdir -p "$work_dir"

# bounded <seconds> <command...>: SIGALRM ends a hung command (no coreutils timeout on macOS).
bounded() { local secs="$1"; shift; perl -e 'alarm shift; exec @ARGV or die "exec: $!"' "$secs" "$@"; }
# sim <args...>: simctl with the query timeout.
sim() {
  # shellcheck disable=SC2086
  bounded "$query_timeout" $simctl_cmd "$@"
}

# 1. a device for the newest installed iOS runtime.
udid="${IOS_SIM_UDID:-}"
runtime=""
if [ -z "$udid" ]; then
  echo "== simctl list (timeout ${query_timeout}s)"
  runtimes_json="$(sim list runtimes available -j)" || {
    echo "simctl did not answer within ${query_timeout}s: CoreSimulator is unavailable on this host" >&2
    exit 3
  }
  runtime="$(printf '%s' "$runtimes_json" | python3 -I -c '
import json, sys
rts = [r for r in json.load(sys.stdin)["runtimes"] if r.get("isAvailable") and r["identifier"].startswith("com.apple.CoreSimulator.SimRuntime.iOS-")]
rts.sort(key=lambda r: [int(p) for p in r["version"].split(".")])
print(rts[-1]["identifier"] if rts else "")
')"
  [ -n "$runtime" ] || { echo "no iOS Simulator runtime installed (Xcode > Settings > Components)" >&2; exit 3; }
  udid="$(sim list devices -j | NAME="$name" RUNTIME="$runtime" python3 -I -c '
import json, os, sys
for d in json.load(sys.stdin)["devices"].get(os.environ["RUNTIME"], []):
    if d["name"] == os.environ["NAME"] and d.get("isAvailable", True):
        print(d["udid"]); break
')"
  if [ -z "$udid" ]; then
    echo "== create device $name ($devicetype, $runtime)"
    udid="$(sim create "$name" "$devicetype" "$runtime")"
  fi
fi
echo "simulator: $udid ${runtime:+(runtime $runtime)}"

# 2. build the test bundle against the XCFramework's simulator slice.
build_log="$work_dir/build-for-testing.log"
echo "== build-for-testing (iOS Simulator, arm64); log: $build_log"
(
  cd crates/symvault-ffi/swift
  # shellcheck disable=SC2086
  SYMVAULT_FFI_XCFRAMEWORK="$framework" bounded "$test_timeout" $xcodebuild_cmd build-for-testing \
    -scheme SymvaultFFI \
    -destination 'generic/platform=iOS Simulator' ARCHS=arm64 \
    -derivedDataPath "$work_dir/DerivedData" \
    -clonedSourcePackagesDirPath "$work_dir/SourcePackages"
) > "$build_log" 2>&1 || {
  tail -n 30 "$build_log" >&2
  echo "build-for-testing failed, full log: $build_log" >&2
  exit 1
}
products="$work_dir/DerivedData/Build/Products/Debug-iphonesimulator"
bundle="$products/SymvaultFFITests.xctest"
[ -d "$bundle" ] || { echo "no test bundle at $bundle" >&2; exit 1; }
echo "bundle: $(lipo -archs "$bundle/SymvaultFFITests") $(xcrun vtool -show-build "$bundle/SymvaultFFITests" | awk '/platform/ { print $2 }')"

# 3. run it inside the simulator.
developer="$(xcode-select -p)/Platforms/iPhoneSimulator.platform/Developer"
sdk="$developer/SDKs/iPhoneSimulator.sdk"
booted_here=0
if ! sim list devices | grep -F "($udid)" | grep -q Booted; then
  sim boot "$udid"
  booted_here=1
fi
cleanup() { if [ "$booted_here" = 1 ]; then sim shutdown "$udid" >/dev/null 2>&1 || true; fi; }
trap cleanup EXIT

log="$work_dir/xctest-spawn.log"
echo "== simctl spawn xctest (timeout ${test_timeout}s); log: $log"
set +e
# shellcheck disable=SC2086
SIMCTL_CHILD_DYLD_FRAMEWORK_PATH="$developer/Library/Frameworks:$developer/Library/PrivateFrameworks:$sdk/Developer/Library/Frameworks" \
SIMCTL_CHILD_DYLD_LIBRARY_PATH="$developer/usr/lib:$sdk/Developer/usr/lib" \
  bounded "$test_timeout" $simctl_cmd spawn "$udid" "$developer/Library/Xcode/Agents/xctest" "$bundle" > "$log" 2>&1
status=$?
set -e
tail -n 22 "$log"
if [ "$status" -ne 0 ]; then
  echo "xctest in the simulator failed (exit $status), full log: $log" >&2
  exit "$status"
fi
# A green run that replayed nothing is not a pass.
# The expected totals come from the fixture, so a re-recorded fixture cannot
# leave a stale number here.
fixture="$repo_root/testdata/port/ffi/mobilebind.json"
expected="$(python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); print("%d steps over %d cases" % (sum(d["step_counts"].values()), len(d["cases"])))' "$fixture")"
grep -qF "FFI-001 swift replayed $expected" "$log" || {
  echo "xctest exited 0 but the replay line 'FFI-001 swift replayed $expected' is missing: $log" >&2
  exit 1
}
echo "OK ffi-ios-simulator-test: $expected replayed on $udid via the XCFramework iOS-Simulator slice"
