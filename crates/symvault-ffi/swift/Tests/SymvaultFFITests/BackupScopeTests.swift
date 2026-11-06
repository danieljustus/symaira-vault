import Foundation
import XCTest

@testable import SymvaultFFI

/// FFI-001: `withBackupDirectory` is a scoped swap. It restores whatever the
/// thread had before it (set through the C ABI, or by an enclosing scope), on
/// return and on throw. Observed through the data-safety gate: the first write
/// to a marker-less vault drops its backup archive in the directory in effect.
final class BackupScopeTests: XCTestCase {
    private var root: URL!
    private var vault: URL!
    private var identity = ""
    private var savedXDG: String?

    private struct Boom: Error {}

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory
            .appendingPathComponent("BackupScopeTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        // A leaked/cleared override must land in this sandbox, never in $HOME.
        savedXDG = ProcessInfo.processInfo.environment["XDG_STATE_HOME"]
        setenv("XDG_STATE_HOME", fallback.path, 1)
        try SymvaultFFI.setBackupDir("")
        try SymvaultFFI.setThreadBackupDir("")
        vault = root.appendingPathComponent("vault")
        try SymvaultFFI.setThreadBackupDir(root.appendingPathComponent("setup").path)
        try SymvaultFFI.initVault(vaultDir: vault.path, passphrase: "correct horse")
        identity = try SymvaultFFI.openVaultWithPassphrase(vaultDir: vault.path, passphrase: "correct horse")
        try SymvaultFFI.setThreadBackupDir("")
    }

    override func tearDownWithError() throws {
        try? SymvaultFFI.setThreadBackupDir("")
        try? SymvaultFFI.setBackupDir("")
        if let savedXDG { setenv("XDG_STATE_HOME", savedXDG, 1) } else { unsetenv("XDG_STATE_HOME") }
        try? FileManager.default.removeItem(at: root)
    }

    private var fallback: URL { root.appendingPathComponent("xdg") }
    private func dir(_ name: String) -> URL { root.appendingPathComponent(name) }

    /// Writes an entry into a vault made marker-less again, so exactly one backup
    /// lands in the directory currently in effect.
    private func writeUnmarked(_ name: String) throws {
        let marker = vault.appendingPathComponent(".symvault-rust")
        if FileManager.default.fileExists(atPath: marker.path) { try FileManager.default.removeItem(at: marker) }
        try SymvaultFFI.writeEntryJSON(
            vaultDir: vault.path, entryPath: name, entryJSON: #"{"data":{"user":"alice"}}"#,
            identity: identity)
    }

    private func archives(_ url: URL) -> Int {
        (try? FileManager.default.contentsOfDirectory(atPath: url.path))?.count ?? 0
    }

    func testScopeRestoresAnOverrideSetThroughTheCApi() throws {
        let cSet = dir("c-set"), scoped = dir("scoped")
        try SymvaultFFI.setThreadBackupDir(cSet.path)
        try SymvaultFFI.withBackupDirectory(scoped.path) { try writeUnmarked("inside") }
        XCTAssertEqual(archives(scoped), 1)
        // Back outside: the C-set directory is in effect again, not the default.
        try writeUnmarked("after")
        XCTAssertEqual(archives(cSet), 1, "the C-set override must survive the Swift scope")
        XCTAssertEqual(archives(fallback.appendingPathComponent("symvault/backups")), 0)
        XCTAssertEqual(archives(scoped), 1)
    }

    func testMixedCAndSwiftNestingRestoresEachLevel() throws {
        let cSet = dir("c-set"), outer = dir("outer"), inner = dir("inner")
        try SymvaultFFI.setThreadBackupDir(cSet.path)
        try SymvaultFFI.withBackupDirectory(outer.path) {
            try SymvaultFFI.withBackupDirectory(inner.path) { try writeUnmarked("innermost") }
            XCTAssertEqual(archives(inner), 1)
            try writeUnmarked("middle")
            XCTAssertEqual(archives(outer), 1, "back in the outer scope after the inner one")
        }
        try writeUnmarked("outside")
        XCTAssertEqual(archives(cSet), 1)
        XCTAssertEqual([archives(inner), archives(outer), archives(cSet)], [1, 1, 1])
    }

    func testThrowingBodyAndRefusedScopeStillRestore() throws {
        let cSet = dir("c-set"), scoped = dir("scoped")
        try SymvaultFFI.setThreadBackupDir(cSet.path)
        XCTAssertThrowsError(try SymvaultFFI.withBackupDirectory(scoped.path) { throw Boom() }) {
            XCTAssertTrue($0 is Boom)
        }
        // Rejected before anything is installed: also leaves the C value alone.
        XCTAssertThrowsError(try SymvaultFFI.withBackupDirectory("") { () -> Void in })
        XCTAssertThrowsError(try SymvaultFFI.withBackupDirectory("relative") { () -> Void in })
        try writeUnmarked("after")
        XCTAssertEqual(archives(cSet), 1)
        XCTAssertEqual(archives(scoped), 0)
    }

    func testScopeOverAClearedThreadRestoresNoOverride() throws {
        let scoped = dir("scoped")
        try SymvaultFFI.withBackupDirectory(scoped.path) { try writeUnmarked("inside") }
        try writeUnmarked("after")
        XCTAssertEqual(archives(scoped), 1)
        XCTAssertEqual(archives(fallback.appendingPathComponent("symvault/backups")), 1,
                       "no override is left behind: the process default applies")
    }

    func testARefusedPopStillRestoresThroughTheUnwind() throws {
        let cSet = dir("c-set"), scoped = dir("scoped")
        try SymvaultFFI.setThreadBackupDir(cSet.path)
        let token = try SymvaultFFI.pushThreadBackupDir(scoped.path)
        // A leaked inner scope makes the outer pop refuse.
        _ = try SymvaultFFI.pushThreadBackupDir(dir("leaked").path)
        var reports: [String] = []
        SymvaultFFI.closeBackupScope(token) { reports.append($0) }
        XCTAssertEqual(reports.count, 1, "the refused pop is reported: \(reports)")
        // The unwind put the C-set value back and dropped the leaked scope.
        try writeUnmarked("after")
        XCTAssertEqual(archives(cSet), 1)
        XCTAssertEqual(archives(scoped), 0)
        XCTAssertEqual(archives(dir("leaked")), 0)
        // The scope is closed now: neither pop nor unwind accepts the token.
        var again: [String] = []
        SymvaultFFI.closeBackupScope(token) { again.append($0) }
        XCTAssertEqual(again.count, 2)
    }
}
