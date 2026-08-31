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

Der lokale technische Preflight baut das Go-Mobile-Framework und einen
unsignierten `iphoneos`-Build. Archiv, Distribution-Signing und Upload werden
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

Auf Daniels Mac wird automatisch ein installiertes Release-Xcode verwendet.
Ein Beta-Xcode ist nur ein Fallback für lokale Builds; Apple kann Beta-SDKs
beim Upload ablehnen.

```bash
./scripts/ios-testflight.sh preflight
```

Das erledigt:

1. `Vaultcore.xcframework` unter `client/.build/mobilecore` erzeugen, falls es
   fehlt.
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
  -- env DEVELOPER_DIR=/Applications/Xcode-26.6.app/Contents/Developer \
  ./scripts/ios-testflight.sh archive

symvault run \
  --env ASC_API_KEY=apple-developer/notary-api-key.password \
  --env ASC_KEY_ID=apple-developer/notary-api-key-id.password \
  --env ASC_ISSUER_ID=apple-developer/notary-api-issuer-id.password \
  -- env DEVELOPER_DIR=/Applications/Xcode-26.6.app/Contents/Developer \
  ./scripts/ios-testflight.sh upload
```

Für einen lokalen Export ohne Upload heißt der letzte Befehl `export`; danach
liegt die IPA unter `client/.build/testflight/export/`.

## Wichtige Grenzen

- Der erste TestFlight-Build ist `1.0 (1)` aus `client/project.yml` und passt
  zur bereits angelegten App-Store-Connect-Version.
- Jeder weitere Upload derselben Version braucht eine höhere Build-Nummer.
- Das Go-Mobile-Framework liegt absichtlich unter `.build/` und wird nicht ins
  Repository eingecheckt.
- Xcode 27 Beta ist für diesen Upload nicht zulässig; Release-Xcode verwenden.
- Apple-Passwort und 2FA-Codes niemals in Chat, Commit oder Klartextdateien
  eingeben.
