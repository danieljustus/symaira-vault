import Foundation
import SymvaultFFI

/// iOS vault core. Talks to the Rust `symvault-ffi` core (`SymvaultFFI`, a
/// narrow C ABI over the same 13 operations the former gomobile
/// `pkg/mobilebind` exposed; ADR 0031) instead of shelling out to the
/// `symvault` binary, because iOS cannot spawn subprocesses. All payloads cross
/// the FFI boundary as JSON strings per ADR 0006 D2.
public enum MobileVaultCoreError: Error, LocalizedError, Sendable {
    case frameworkError(String)
    case invalidResponse

    public var errorDescription: String? {
        switch self {
        case .frameworkError(let msg): return msg
        case .invalidResponse: return "Invalid response from the vault core"
        }
    }
}

public struct MobileVaultEntry: Sendable, Identifiable, Hashable {
    public let id: String
    public let path: String
    public let fields: [String: String]
    public let metadata: [String: String]
}

public struct MobileVaultCore: Sendable {
    public let vaultDirectory: URL
    /// Where the core's D1 pre-migration backup goes; `nil` means
    /// `MobileVaultBackup.defaultDirectory()` (Application Support, excluded
    /// from iCloud backup).
    public let backupDirectory: URL?

    public init(vaultDirectory: URL, backupDirectory: URL? = nil) {
        self.vaultDirectory = vaultDirectory
        self.backupDirectory = backupDirectory
    }

    /// Runs one core call and reports every failure as `.frameworkError` with
    /// the core's text, the surface callers saw from the gomobile `NSError`
    /// (`localizedDescription` was the Go error text; the Rust core returns the
    /// same text, `SymvaultFFIError.go`). Contained panics and unusable
    /// arguments are reported the same way.
    private func core<T>(_ body: () throws -> T) throws -> T {
        do {
            return try body()
        } catch let error as SymvaultFFIError {
            throw MobileVaultCoreError.frameworkError(error.description)
        }
    }

    /// A core call that opens or writes the vault: first points the Rust core
    /// at the backup-excluded directory (the data-safety gate may back up a
    /// Go-created vault before its first write), then runs `body`. When the
    /// directory cannot be prepared the call fails and nothing touches the
    /// vault.
    private func vaultCore<T>(_ body: () throws -> T) throws -> T {
        try core {
            let directory = try backupDirectory ?? MobileVaultBackup.defaultDirectory()
            try MobileVaultBackup.prepare(directory)
            return try SymvaultFFI.withBackupDirectory(directory.standardizedFileURL.path, body)
        }
    }

    public func generateIdentity() throws -> String {
        try core { try SymvaultFFI.generateIdentity() }
    }

    public func publicKey(for identity: String) throws -> String {
        try core { try SymvaultFFI.identityPublicKey(identity: identity) }
    }

    /// The Go function could not fail and the signature is non-throwing; a
    /// boundary failure (not reachable for valid UTF-8 input) yields an empty
    /// fingerprint rather than a crash.
    public func fingerprint(of pubkey: String) -> String {
        (try? SymvaultFFI.publicKeyFingerprint(pubkey: pubkey)) ?? ""
    }

    public func initVault(passphrase: String) throws {
        try vaultCore { try SymvaultFFI.initVault(vaultDir: vaultDirectory.path, passphrase: passphrase) }
    }

    /// Unlocks the vault and returns the decrypted master identity string.
    public func open(passphrase: String) throws -> String {
        try vaultCore {
            try SymvaultFFI.openVaultWithPassphrase(
                vaultDir: vaultDirectory.path, passphrase: passphrase)
        }
    }

    public func readEntry(path: String, identity: String) throws -> MobileVaultEntry {
        let json = try vaultCore {
            try SymvaultFFI.readEntryJSON(
                vaultDir: vaultDirectory.path, entryPath: path, identity: identity)
        }
        guard let data = json.data(using: .utf8) else {
            throw MobileVaultCoreError.invalidResponse
        }
        let decoded = try JSONDecoder().decode(BridgedEntry.self, from: data)
        // The core's entry JSON carries no `path` (the bridge clears it), so
        // the requested path is the entry's identity.
        let entryPath = decoded.path ?? path
        return MobileVaultEntry(
            id: entryPath,
            path: entryPath,
            fields: decoded.data.mapValues { $0.value },
            metadata: decoded.metadata ?? [:]
        )
    }

    public func listEntries(prefix: String = "", identity: String) throws -> [String] {
        let json = try vaultCore {
            try SymvaultFFI.listEntriesJSON(
                vaultDir: vaultDirectory.path, prefix: prefix, identity: identity)
        }
        guard let data = json.data(using: .utf8) else {
            throw MobileVaultCoreError.invalidResponse
        }
        return try JSONDecoder().decode([String].self, from: data)
    }

    public func verifyManifest(identity: String) throws -> Bool {
        try vaultCore {
            try SymvaultFFI.verifyManifestIntegrity(
                vaultDir: vaultDirectory.path, identity: identity)
        }
    }

    private struct BridgedEntry: Decodable {
        let path: String?
        let data: [String: AnyJSON]
        let metadata: [String: String]?
    }

    private enum AnyJSON: Decodable {
        case string(String)
        case number(Double)
        case bool(Bool)

        init(from decoder: Decoder) throws {
            let c = try decoder.singleValueContainer()
            if let v = try? c.decode(String.self) { self = .string(v) }
            else if let v = try? c.decode(Bool.self) { self = .bool(v) }
            else if let v = try? c.decode(Double.self) { self = .number(v) }
            else { self = .string("") }
        }

        var value: String {
            switch self {
            case .string(let s): return s
            case .number(let n):
                // Integral doubles in Int64 range print as their exact integer
                // value (Go stores numbers as float64); others, and -0 (whose
                // sign Int64 would drop), use Swift's shortest round-trip form.
                if n == n.rounded(), abs(n) < 0x1p63, !(n == 0 && n.sign == .minus) {
                    return String(Int64(n))
                }
                return "\(n)"
            case .bool(let b): return b ? "true" : "false"
            }
        }
    }
}
