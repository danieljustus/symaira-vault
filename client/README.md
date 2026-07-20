# Symvault for macOS

Native SwiftUI client for the public, self-hosted `symvault` runtime. The
client is split into `SymvaultKit` (CLI contract) and `SymvaultFeature`
(reusable UI) so the same feature can be embedded in Symaira Hub.

## Build

```bash
cd ..
make build
cd client
xcodegen generate
DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer \
  xcodebuild -project Symvault.xcodeproj -scheme Symvault -scmProvider system build
```

For the reusable packages and unit tests:

```bash
swift build
swift test
```

The Xcode build embeds the locally built `symvault` binary in the app bundle.
During package development, the client can also discover `symvault` beside the
executable, on `PATH`, or in the standard Homebrew prefixes.
