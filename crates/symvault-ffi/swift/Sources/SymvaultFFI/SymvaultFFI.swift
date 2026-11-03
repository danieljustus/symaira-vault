import CSymvaultFFI
import Foundation

/// A failure reported by the Rust core. `.go` carries the exact text the Go
/// `pkg/mobilebind` function returned for the same input.
public enum SymvaultFFIError: Error, Equatable, CustomStringConvertible {
    case go(String)
    case panic(String)
    case badArguments(String)

    public var description: String {
        switch self {
        case .go(let text), .panic(let text), .badArguments(let text): return text
        }
    }
}

/// Swift surface over the C ABI; one method per `pkg/mobilebind` function.
public enum SymvaultFFI {
    /// ABI revision of the linked library.
    public static var abiVersion: UInt32 { symvault_ffi_abi_version() }

    public static func generateIdentity() throws -> String {
        try text(call { out, err in symvault_generate_identity(out, err) })
    }

    public static func identityPublicKey(identity: String) throws -> String {
        try text(
            call([.text(identity)]) { a, out, err in
                symvault_identity_public_key(a[0].0, a[0].1, out, err)
            })
    }

    /// Cannot fail on the Go side; any unexpected boundary failure throws.
    public static func publicKeyFingerprint(pubkey: String) throws -> String {
        try text(
            call([.text(pubkey)]) { a, out, err in
                symvault_public_key_fingerprint(a[0].0, a[0].1, out, err)
            })
    }

    public static func encryptWithPublicKey(recipient: String, plaintext: Data) throws -> Data {
        try call([.text(recipient), .data(plaintext)]) { a, out, err in
            symvault_encrypt_with_public_key(a[0].0, a[0].1, a[1].0, a[1].1, out, err)
        }
    }

    public static func decryptWithIdentity(identity: String, ciphertext: Data) throws -> Data {
        try call([.text(identity), .data(ciphertext)]) { a, out, err in
            symvault_decrypt_with_identity(a[0].0, a[0].1, a[1].0, a[1].1, out, err)
        }
    }

    public static func encryptWithPassphrase(passphrase: String, plaintext: Data) throws -> Data {
        try call([.text(passphrase), .data(plaintext)]) { a, out, err in
            symvault_encrypt_with_passphrase(a[0].0, a[0].1, a[1].0, a[1].1, out, err)
        }
    }

    public static func decryptWithPassphrase(passphrase: String, ciphertext: Data) throws -> Data {
        try call([.text(passphrase), .data(ciphertext)]) { a, out, err in
            symvault_decrypt_with_passphrase(a[0].0, a[0].1, a[1].0, a[1].1, out, err)
        }
    }

    public static func initVault(vaultDir: String, passphrase: String) throws {
        _ = try call([.text(vaultDir), .text(passphrase)]) { a, _, err in
            symvault_init_vault(a[0].0, a[0].1, a[1].0, a[1].1, err)
        }
    }

    /// Where the verified pre-migration backup of a Go-created vault goes
    /// (call before the first write; an empty string restores the default).
    /// Keeping it out of iCloud backup is the host's responsibility.
    public static func setBackupDir(_ dir: String) throws {
        _ = try call([.text(dir)]) { a, _, err in
            symvault_set_backup_dir(a[0].0, a[0].1, err)
        }
    }

    /// Applies a thread-local backup directory for the synchronous body, even
    /// when another caller changes the process-wide default. Do not suspend.
    public static func withBackupDirectory<T>(_ dir: String, _ body: () throws -> T) throws -> T {
        guard !dir.isEmpty else { throw SymvaultFFIError.badArguments("backup directory is empty") }
        let key = "org.symaira.symvault.backup-scope"
        guard Thread.current.threadDictionary[key] == nil else {
            throw SymvaultFFIError.badArguments("nested backup directory scope")
        }
        try setThreadBackupDir(dir)
        Thread.current.threadDictionary[key] = true
        defer {
            try? setThreadBackupDir("")
            Thread.current.threadDictionary.removeObject(forKey: key)
        }
        return try body()
    }

    private static func setThreadBackupDir(_ dir: String) throws {
        _ = try call([.text(dir)]) { a, _, err in
            symvault_set_thread_backup_dir(a[0].0, a[0].1, err)
        }
    }

    public static func openVaultWithPassphrase(vaultDir: String, passphrase: String) throws
        -> String
    {
        try text(
            call([.text(vaultDir), .text(passphrase)]) { a, out, err in
                symvault_open_vault_with_passphrase(a[0].0, a[0].1, a[1].0, a[1].1, out, err)
            })
    }

    public static func readEntryJSON(vaultDir: String, entryPath: String, identity: String) throws
        -> String
    {
        try text(
            call([.text(vaultDir), .text(entryPath), .text(identity)]) { a, out, err in
                symvault_read_entry_json(a[0].0, a[0].1, a[1].0, a[1].1, a[2].0, a[2].1, out, err)
            })
    }

    public static func writeEntryJSON(
        vaultDir: String, entryPath: String, entryJSON: String, identity: String
    ) throws {
        _ = try call([.text(vaultDir), .text(entryPath), .text(entryJSON), .text(identity)]) {
            a, _, err in
            symvault_write_entry_json(
                a[0].0, a[0].1, a[1].0, a[1].1, a[2].0, a[2].1, a[3].0, a[3].1, err)
        }
    }

    public static func listEntriesJSON(vaultDir: String, prefix: String, identity: String) throws
        -> String
    {
        try text(
            call([.text(vaultDir), .text(prefix), .text(identity)]) { a, out, err in
                symvault_list_entries_json(a[0].0, a[0].1, a[1].0, a[1].1, a[2].0, a[2].1, out, err)
            })
    }

    public static func verifyManifestIntegrity(vaultDir: String, identity: String) throws -> Bool {
        var ok: Int32 = 0
        _ = try call([.text(vaultDir), .text(identity)]) { a, _, err in
            symvault_verify_manifest_integrity(a[0].0, a[0].1, a[1].0, a[1].1, &ok, err)
        }
        return ok == 1
    }

    // MARK: - plumbing

    private enum Argument {
        case text(String)
        case data(Data)
    }

    private typealias Bytes = (UnsafePointer<UInt8>?, Int)

    private static func text(_ data: Data) throws -> String {
        guard let value = String(data: data, encoding: .utf8) else {
            throw SymvaultFFIError.badArguments("result is not valid UTF-8")
        }
        return value
    }

    /// Lends every argument as a (pointer, length) pair for the duration of `body`.
    private static func lend<R>(
        _ arguments: ArraySlice<Argument>, _ lent: [Bytes], _ body: ([Bytes]) -> R
    ) -> R {
        guard let first = arguments.first else { return body(lent) }
        let rest = arguments.dropFirst()
        switch first {
        case .text(var string):
            return string.withUTF8 { buffer in
                lend(rest, lent + [(buffer.baseAddress, buffer.count)], body)
            }
        case .data(let data):
            return data.withUnsafeBytes { raw in
                let base = raw.bindMemory(to: UInt8.self).baseAddress
                return lend(rest, lent + [(base, raw.count)], body)
            }
        }
    }

    private static func take(_ buffer: SvBuf) -> Data {
        guard let pointer = buffer.ptr, buffer.len > 0 else { return Data() }
        let data = Data(bytes: pointer, count: buffer.len)
        symvault_buf_free(buffer)
        return data
    }

    @discardableResult
    private static func call(
        _ arguments: [Argument],
        _ invoke: ([Bytes], UnsafeMutablePointer<SvBuf>, UnsafeMutablePointer<SvBuf>) -> Int32
    ) throws -> Data {
        var out = SvBuf(ptr: nil, len: 0)
        var err = SvBuf(ptr: nil, len: 0)
        let status = lend(arguments[...], []) { pairs in
            invoke(pairs, &out, &err)
        }
        let result = take(out)
        let message = String(data: take(err), encoding: .utf8) ?? ""
        switch status {
        case 0: return result
        case 1: throw SymvaultFFIError.go(message)
        case 2: throw SymvaultFFIError.panic(message)
        default: throw SymvaultFFIError.badArguments(message)
        }
    }

    /// Zero-argument form (`GenerateIdentity`).
    @discardableResult
    private static func call(
        _ invoke: (UnsafeMutablePointer<SvBuf>, UnsafeMutablePointer<SvBuf>) -> Int32
    ) throws -> Data {
        try call([]) { (_: [Bytes], out: UnsafeMutablePointer<SvBuf>, err: UnsafeMutablePointer<SvBuf>) in
            invoke(out, err)
        }
    }
}
