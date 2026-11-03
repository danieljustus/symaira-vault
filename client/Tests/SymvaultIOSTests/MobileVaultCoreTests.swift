import SymvaultFFI
import XCTest

@testable import SymvaultIOS

/// Runs `MobileVaultCore` against the real Rust core (`SymvaultFFI`), the
/// code the iOS app ships. Uses a throwaway vault directory per test.
final class MobileVaultCoreTests: XCTestCase {
    private var directory: URL!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("MobileVaultCoreTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        // The core's backup directory is process-wide state.
        try? SymvaultFFI.setBackupDir("")
        try? FileManager.default.removeItem(at: directory)
    }

    /// Keeps every test's D1 backups inside its own throwaway directory.
    private var backups: URL { directory.appendingPathComponent("backups") }

    private func isExcludedFromBackup(_ url: URL) throws -> Bool {
        try url.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup ?? false
    }

    /// The host sets the backup directory (created `0700`, excluded from
    /// iCloud backup) before the core opens or writes the vault, and the Rust
    /// gate then really writes its pre-migration backup there.
    func testBackupDirectoryIsExcludedFromBackupAndUsedByTheDataSafetyGate() throws {
        let vault = directory.appendingPathComponent("vault")
        let chosen = backups.appendingPathComponent("nested")
        let core = MobileVaultCore(vaultDirectory: vault, backupDirectory: chosen)
        XCTAssertFalse(FileManager.default.fileExists(atPath: chosen.path))
        try core.initVault(passphrase: "correct horse")

        var isDirectory: ObjCBool = false
        XCTAssertTrue(FileManager.default.fileExists(atPath: chosen.path, isDirectory: &isDirectory))
        XCTAssertTrue(isDirectory.boolValue)
        XCTAssertTrue(try isExcludedFromBackup(chosen))
        let attributes = try FileManager.default.attributesOfItem(atPath: chosen.path)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o700)

        // Turn the vault into one a Go build created (no Rust marker), then
        // let the app's next open point the core at the directory and write.
        let identity = try core.open(passphrase: "correct horse")
        try FileManager.default.removeItem(at: vault.appendingPathComponent(".symvault-rust"))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: chosen.path), [])
        try SymvaultFFI.writeEntryJSON(
            vaultDir: vault.path, entryPath: "site/example",
            entryJSON: #"{"data":{"user":"alice"}}"#, identity: identity)

        let archives = try FileManager.default.contentsOfDirectory(atPath: chosen.path)
        XCTAssertEqual(archives.count, 1, "\(archives)")
        XCTAssertTrue(archives[0].hasPrefix("pre-rust-") && archives[0].hasSuffix(".tar.gz"), "\(archives)")
        XCTAssertTrue(
            FileManager.default.fileExists(atPath: vault.appendingPathComponent(".symvault-rust").path))
    }

    /// With no explicit directory the backup goes to Application Support (never
    /// Caches, which the system purges), under the app's own name.
    func testDefaultBackupDirectoryIsApplicationSupportNotCaches() throws {
        let url = try MobileVaultBackup.defaultDirectory()
        let support = try FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: false)
        XCTAssertEqual(url.deletingLastPathComponent().standardizedFileURL, support.standardizedFileURL)
        XCTAssertEqual(url.lastPathComponent, "symaira-vault-backups")
        XCTAssertFalse(url.path.contains("/Caches/"))
    }

    /// An unusable backup directory stops the call before the core touches the
    /// vault: no half-protected write.
    func testUnusableBackupDirectoryFailsTheCallBeforeTheVaultIsTouched() throws {
        let blocker = directory.appendingPathComponent("not-a-directory")
        try Data("x".utf8).write(to: blocker)
        let vault = directory.appendingPathComponent("vault")
        let core = MobileVaultCore(
            vaultDirectory: vault, backupDirectory: blocker.appendingPathComponent("backups"))
        XCTAssertThrowsError(try core.initVault(passphrase: "correct horse"))
        XCTAssertFalse(FileManager.default.fileExists(atPath: vault.path))
    }

    func testIdentityKeyAndFingerprint() throws {
        let core = MobileVaultCore(vaultDirectory: directory, backupDirectory: backups)
        let identity = try core.generateIdentity()
        XCTAssertTrue(identity.hasPrefix("AGE-SECRET-KEY-1"))
        let pub = try core.publicKey(for: identity)
        XCTAssertTrue(pub.hasPrefix("age1"))
        XCTAssertFalse(core.fingerprint(of: pub).isEmpty)
        XCTAssertEqual(core.fingerprint(of: pub), core.fingerprint(of: pub))
    }

    func testInitOpenReadListVerify() throws {
        let vault = directory.appendingPathComponent("vault")
        let core = MobileVaultCore(vaultDirectory: vault, backupDirectory: backups)
        try core.initVault(passphrase: "correct horse")
        let identity = try core.open(passphrase: "correct horse")
        XCTAssertTrue(identity.hasPrefix("AGE-SECRET-KEY-1"))

        try SymvaultFFI.writeEntryJSON(
            vaultDir: vault.path, entryPath: "site/example",
            entryJSON: #"{"data":{"user":"alice","pin":42,"on":true,"account":1234567890123,"rate":1.25,"neg":-42,"negzero":-0.0,"p53":9007199254740992,"p54":18014398509481984}}"#,
            identity: identity)

        XCTAssertEqual(try core.listEntries(identity: identity), ["site/example"])
        XCTAssertEqual(try core.listEntries(prefix: "other", identity: identity), [])
        let entry = try core.readEntry(path: "site/example", identity: identity)
        XCTAssertEqual(entry.id, "site/example")
        XCTAssertEqual(entry.path, "site/example")
        XCTAssertEqual(entry.fields["user"], "alice")
        XCTAssertEqual(entry.fields["pin"], "42")
        XCTAssertEqual(entry.fields["on"], "true")
        // More than six significant digits must not collapse to "1.23457e+12".
        XCTAssertEqual(entry.fields["account"], "1234567890123")
        XCTAssertEqual(entry.fields["rate"], "1.25")
        XCTAssertEqual(entry.fields["neg"], "-42")
        XCTAssertEqual(entry.fields["negzero"], "-0.0")
        XCTAssertEqual(entry.fields["p53"], "9007199254740992")
        XCTAssertEqual(entry.fields["p54"], "18014398509481984")
        XCTAssertTrue(try core.verifyManifest(identity: identity))
    }

    /// Failures keep the surface callers saw from the gomobile `NSError`: a
    /// `.frameworkError` whose text (also `localizedDescription`) is the core's.
    func testErrorsSurfaceAsFrameworkErrorWithCoreText() throws {
        let vault = directory.appendingPathComponent("vault")
        let core = MobileVaultCore(vaultDirectory: vault, backupDirectory: backups)
        try core.initVault(passphrase: "right")

        XCTAssertThrowsError(try core.open(passphrase: "wrong")) { error in
            guard case MobileVaultCoreError.frameworkError(let text) = error else {
                return XCTFail("expected frameworkError, got \(error)")
            }
            XCTAssertEqual(
                text, "load identity: zero-key recovery requires a trusted recipients.txt")
            XCTAssertEqual(error.localizedDescription, text)
        }
        XCTAssertThrowsError(try core.publicKey(for: "not an identity")) { error in
            guard case MobileVaultCoreError.frameworkError(let text) = error else {
                return XCTFail("expected frameworkError, got \(error)")
            }
            XCTAssertFalse(text.isEmpty)
        }
        XCTAssertThrowsError(try core.readEntry(path: "missing", identity: "bad"))
    }
}
