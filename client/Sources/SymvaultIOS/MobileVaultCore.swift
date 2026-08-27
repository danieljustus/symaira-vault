#if os(iOS)
import Foundation
import Vaultcore

/// iOS vault core. Talks to the embedded `Vaultcore` XCFramework (a gomobile
/// bind of `pkg/mobilebind`) instead of shelling out to the `symvault` binary,
/// because iOS cannot spawn subprocesses. All payloads cross the FFI boundary
/// as JSON strings per ADR 0006 D2.
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

    public init(vaultDirectory: URL) {
        self.vaultDirectory = vaultDirectory
    }

    private func run(_ body: (NSErrorPointer) throws -> Void) throws {
        var err: NSError?
        try body(&err)
        if let err {
            throw MobileVaultCoreError.frameworkError(err.localizedDescription)
        }
    }

    public func generateIdentity() throws -> String {
        var err: NSError?
        let s = MobilebindGenerateIdentity(&err)
        if let err { throw MobileVaultCoreError.frameworkError(err.localizedDescription) }
        return s as String
    }

    public func publicKey(for identity: String) throws -> String {
        var err: NSError?
        let s = MobilebindIdentityPublicKey(identity, &err)
        if let err { throw MobileVaultCoreError.frameworkError(err.localizedDescription) }
        return s as String
    }

    public func fingerprint(of pubkey: String) -> String {
        MobilebindPublicKeyFingerprint(pubkey) as String
    }

    public func initVault(passphrase: String) throws {
        var err: NSError?
        let ok = MobilebindInitVault(vaultDirectory.path, passphrase, &err)
        if let err { throw MobileVaultCoreError.frameworkError(err.localizedDescription) }
        if !ok { throw MobileVaultCoreError.invalidResponse }
    }

    /// Unlocks the vault and returns the decrypted master identity string.
    public func open(passphrase: String) throws -> String {
        var err: NSError?
        let id = MobilebindOpenVaultWithPassphrase(vaultDirectory.path, passphrase, &err)
        if let err { throw MobileVaultCoreError.frameworkError(err.localizedDescription) }
        return id as String
    }

    public func readEntry(path: String, identity: String) throws -> MobileVaultEntry {
        var err: NSError?
        let json = MobilebindReadEntryJSON(vaultDirectory.path, path, identity, &err)
        if let err { throw MobileVaultCoreError.frameworkError(err.localizedDescription) }
        guard let data = (json as String).data(using: .utf8) else {
            throw MobileVaultCoreError.invalidResponse
        }
        let decoded = try JSONDecoder().decode(BridgedEntry.self, from: data)
        return MobileVaultEntry(
            id: decoded.path,
            path: decoded.path,
            fields: decoded.data.compactMapValues { "\($0)" },
            metadata: decoded.metadata ?? [:]
        )
    }

    public func listEntries(prefix: String = "", identity: String) throws -> [String] {
        var err: NSError?
        let json = MobilebindListEntriesJSON(vaultDirectory.path, prefix, identity, &err)
        if let err { throw MobileVaultCoreError.frameworkError(err.localizedDescription) }
        guard let data = (json as String).data(using: .utf8) else {
            throw MobileVaultCoreError.invalidResponse
        }
        return try JSONDecoder().decode([String].self, from: data)
    }

    public func verifyManifest(identity: String) throws -> Bool {
        var err: NSError?
        var valid: ObjCBool = false
        let ok = MobilebindVerifyManifestIntegrity(vaultDirectory.path, identity, &valid, &err)
        if let err { throw MobileVaultCoreError.frameworkError(err.localizedDescription) }
        if !ok { throw MobileVaultCoreError.invalidResponse }
        return valid.boolValue
    }

    private struct BridgedEntry: Decodable {
        let path: String
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
            case .number(let n): return String(format: "%g", n)
            case .bool(let b): return b ? "true" : "false"
            }
        }
    }
}
#endif
