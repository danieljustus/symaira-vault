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
        try? FileManager.default.removeItem(at: directory)
    }

    func testIdentityKeyAndFingerprint() throws {
        let core = MobileVaultCore(vaultDirectory: directory)
        let identity = try core.generateIdentity()
        XCTAssertTrue(identity.hasPrefix("AGE-SECRET-KEY-1"))
        let pub = try core.publicKey(for: identity)
        XCTAssertTrue(pub.hasPrefix("age1"))
        XCTAssertFalse(core.fingerprint(of: pub).isEmpty)
        XCTAssertEqual(core.fingerprint(of: pub), core.fingerprint(of: pub))
    }

    func testInitOpenReadListVerify() throws {
        let vault = directory.appendingPathComponent("vault")
        let core = MobileVaultCore(vaultDirectory: vault)
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
        let core = MobileVaultCore(vaultDirectory: vault)
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
