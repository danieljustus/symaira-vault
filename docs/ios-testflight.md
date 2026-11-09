# iOS-TestFlight-Vorbereitung

Diese Anleitung betrifft die iOS-App `SymvaultIOSApp` aus `client/`. Der
Swift-Code liegt weiterhin unter `Sources/SymvaultIOS`.

## Aktueller Stand

- Bundle ID: `com.symaira.vault.ios`
- Produktname: `Symaira Vault`
- Deployment Target: iOS 17
- Signing Team: `M4744F3TAA`
- Testmodus: **Internal Testing**, zunächst nur Daniel
- Export: `client/ExportOptions-TestFlight.plist`
- Upload: `client/ExportOptions-TestFlight-Upload.plist`
- Build-Skript: `scripts/ios-testflight.sh`

Der lokale technische Preflight baut den Rust-Kern als
`SymvaultFFI.xcframework` (UniFFI/C-ABI-Wrapper aus `crates/symvault-ffi`) und
einen unsignierten `iphoneos`-Build. Go ist entfernt; es gibt kein
Go-Mobile-Framework mehr. Archiv, Distribution-Signing und Upload werden
anschließend von Xcode mit dem ASC-Key aus SymVault ausgeführt.

## Bereits in SymVault vorhanden

Die folgenden Einträge sind vorhanden:

- `apple-developer/apple-id`
- `apple-developer/team-id`
- `apple-developer/notary-api-key`
- `apple-developer/notary-api-key-id`
- `apple-developer/notary-api-issuer-id`

Der App-Store-Connect-Key wurde erfolgreich gegen Apples API getestet.

Der gleiche Key wird für `xcodebuild` zur Verwaltung von Zertifikat,
Provisioning-Profil und Upload verwendet. Die Rohwerte verlassen SymVault nur
innerhalb des gestarteten Prozesses.

Ein iOS-Distribution-P12 ist nicht erforderlich: Xcode verwaltet das
Distribution-Zertifikat und das Profil über den ASC-Key. Das vorhandene P12
ist ein macOS-Developer-ID-Zertifikat und wird für iOS nicht verwendet.

## Lokaler Preflight

Auf Daniels Mac wird automatisch ein installiertes Release-Xcode verwendet
(`/Applications/Xcode-*.app`, sonst `/Applications/Xcode.app`; aktuell Xcode 27).
Ein Beta-Xcode ist nur ein Fallback für lokale Builds; Apple kann Beta-SDKs
beim Upload ablehnen. Das gewählte Xcode zeigt `xcode-select -p`; mit
`DEVELOPER_DIR` lässt es sich pro Aufruf überschreiben.

```bash
./scripts/ios-testflight.sh preflight
```

Das erledigt:

1. `SymvaultFFI.xcframework` (Rust-Kern, `crates/symvault-ffi`) über
   `scripts/build-vaultcore.sh` unter `client/.build/mobilecore` bei jedem Lauf
   neu bauen (Cargo baut inkrementell, ein unveränderter Kern kostet Sekunden;
   so landet nie ein veralteter Kern im Upload). Das Swift-Package
   (`client/Package.swift`, Binary-Target `CSymvaultFFI`) und damit
   `SymvaultIOSApp` (`client/project.yml`, Produkt `SymvaultFFI`) binden genau
   diesen Pfad ein. Braucht die gepinnte Rust-Toolchain mit den Targets
   `aarch64-apple-ios` und `aarch64-apple-ios-sim`
   (`rustup target add aarch64-apple-ios aarch64-apple-ios-sim`).
2. Das Xcode-Projekt mit XcodeGen generieren.
3. Swift Package Dependencies auflösen.
4. Einen unsignierten Release-App-Build für `iphoneos` bauen.

## Einmaliger Apple-Schritt

Der App-Record ist in App Store Connect vorhanden und muss vor dem ersten
Upload auf die Projekt-Bundle-ID zeigen:

1. In App Store Connect die App-Informationen öffnen und prüfen:
   - Name: `Symaira Vault`
   - Bundle ID: `com.symaira.vault.ios`
   - SKU: `symaira-vault-ios`
2. Falls Apple es verlangt: die Bundle ID im Developer Portal registrieren.
3. In TestFlight eine interne Testergruppe anlegen und Daniel hinzufügen.

Für Internal Testing ist keine öffentliche TestFlight-URL und kein externer
Beta-Review nötig.

## Signiertes Archiv und Export

Team-ID und ASC-Key werden nur innerhalb des gestarteten Prozesses aus SymVault
injiziert; sie landen nicht in Chat oder Shell-History:

```bash
symvault run \
  --env TEAM_ID=apple-developer/team-id.password \
  --env ASC_API_KEY=apple-developer/notary-api-key.password \
  --env ASC_KEY_ID=apple-developer/notary-api-key-id.password \
  --env ASC_ISSUER_ID=apple-developer/notary-api-issuer-id.password \
  -- ./scripts/ios-testflight.sh archive

symvault run \
  --env ASC_API_KEY=apple-developer/notary-api-key.password \
  --env ASC_KEY_ID=apple-developer/notary-api-key-id.password \
  --env ASC_ISSUER_ID=apple-developer/notary-api-issuer-id.password \
  -- ./scripts/ios-testflight.sh upload
```

Das Skript wählt das Release-Xcode selbst (siehe oben). Soll ein bestimmtes
Xcode verwendet werden, `env DEVELOPER_DIR=<Xcode>.app/Contents/Developer`
vor `./scripts/ios-testflight.sh` setzen (Standard:
`/Applications/Xcode.app/Contents/Developer`, siehe `xcode-select -p`).

Für einen lokalen Export ohne Upload heißt der letzte Befehl `export`; danach
liegt die IPA unter `client/.build/testflight/export/`.

## Wichtige Grenzen

- Der erste TestFlight-Build ist `1.0 (1)` aus `client/project.yml` und passt
  zur bereits angelegten App-Store-Connect-Version.
- Jeder weitere Upload derselben Version braucht eine höhere Build-Nummer:
  `CURRENT_PROJECT_VERSION` in `client/project.yml` muss erhöht werden, sobald
  ein Build mit der aktuellen Nummer bereits hochgeladen wurde (Apple lehnt
  doppelte Build-Nummern ab).
- `SymvaultFFI.xcframework` liegt absichtlich unter `client/.build/mobilecore`
  und wird nicht ins Repository eingecheckt.
- Ein Beta-Xcode ist für diesen Upload nicht zulässig; Release-Xcode
  verwenden (Xcode 27 ist inzwischen das Release).
- Apple-Passwort und 2FA-Codes niemals in Chat, Commit oder Klartextdateien
  eingeben.
