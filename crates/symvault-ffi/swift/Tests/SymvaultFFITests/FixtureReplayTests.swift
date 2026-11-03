import CryptoKit
import Foundation
import XCTest

@testable import SymvaultFFI

/// Replays testdata/port/ffi/mobilebind.json (recorded from the real Go
/// pkg/mobilebind functions) through the Swift binding and the Rust library.
final class FixtureReplayTests: XCTestCase {
    typealias JSON = [String: Any]

    // MARK: fixture location

    static let repositoryRoot: URL = {
        // crates/symvault-ffi/swift/Tests/SymvaultFFITests/<this file>
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        return url
    }()

    /// Foundation's JSON parser drops a U+FEFF at the start of a string, which
    /// would erase the `utf8-bom` case. Park the character on a private-use
    /// scalar while parsing and restore it afterwards.
    static let parkedBOM = Unicode.Scalar(0xE0FF)!

    static func restoreBOM(_ value: Any) -> Any {
        switch value {
        case let text as String:
            return String(
                String.UnicodeScalarView(text.unicodeScalars.map { $0 == parkedBOM ? "\u{FEFF}" : $0 }))
        case let list as [Any]:
            return list.map(restoreBOM)
        case let object as [String: Any]:
            return Dictionary(
                uniqueKeysWithValues: object.map { (restoreBOM($0.key) as! String, restoreBOM($0.value)) })
        default:
            return value
        }
    }

    static func loadJSON(_ name: String) throws -> JSON {
        let url = repositoryRoot.appendingPathComponent("testdata/port/ffi/\(name)")
        let raw = try String(contentsOf: url, encoding: .utf8)
        let parked = String(
            String.UnicodeScalarView(raw.unicodeScalars.map { $0 == "\u{FEFF}" ? parkedBOM : $0 }))
        let object = try JSONSerialization.jsonObject(with: Data(parked.utf8))
        return try XCTUnwrap(restoreBOM(object) as? JSON)
    }

    // MARK: outcome of one bridge call

    struct Outcome {
        var ok = false
        var string: String?
        var bytes: Data?
        var flag: Bool?
        var error = ""
    }

    static let functions = [
        "GenerateIdentity", "IdentityPublicKey", "PublicKeyFingerprint",
        "EncryptWithPublicKey", "DecryptWithIdentity", "EncryptWithPassphrase",
        "DecryptWithPassphrase", "InitVault", "OpenVaultWithPassphrase", "ReadEntryJSON",
        "WriteEntryJSON", "ListEntriesJSON", "VerifyManifestIntegrity",
    ]

    func s(_ args: JSON, _ key: String) -> String { args[key] as? String ?? "" }

    /// `entryJSON`, or the concatenation of `entryJSON_parts` (each text
    /// repeated `repeat` times), so 10 000-level documents stay tiny in the fixture.
    func entryJSON(_ args: JSON) -> String {
        guard let parts = args["entryJSON_parts"] as? [JSON] else { return s(args, "entryJSON") }
        return parts.map { part in
            String(repeating: part["text"] as? String ?? "", count: max(part["repeat"] as? Int ?? 1, 1))
        }.joined()
    }

    func plaintext(_ args: JSON) -> Data {
        if let length = args["plaintext_pattern_len"] as? Int, length > 0 {
            return Data((0..<length).map { UInt8($0 % 251) })
        }
        return Data(base64Encoded: s(args, "plaintext_b64")) ?? Data()
    }

    func ciphertext(_ args: JSON, _ seed: JSON) -> Data {
        guard let reference = args["ciphertext_ref"] as? String else {
            return Data(base64Encoded: s(args, "ciphertext_b64")) ?? Data()
        }
        let parts = reference.split(separator: ":", maxSplits: 1).map(String.init)
        let table = parts[0] == "scrypt" ? "scrypt_ciphertexts_b64" : "x25519_ciphertexts_b64"
        let named = (seed[table] as? JSON)?[parts[1]] as? String ?? ""
        var data = Data(base64Encoded: named) ?? Data()
        if let edit = args["ciphertext_edit"] as? String {
            let pieces = edit.split(separator: ":").map(String.init)
            let offset = Int(pieces[1]) ?? 0
            if pieces[0] == "flip" {
                data[offset] ^= 0x80
            } else if pieces[0] == "truncate" {
                data = data.prefix(offset)
            }
        }
        return data
    }

    func call(_ function: String, _ args: JSON, _ seed: JSON) -> Outcome {
        var outcome = Outcome()
        do {
            switch function {
            case "GenerateIdentity":
                outcome.string = try SymvaultFFI.generateIdentity()
            case "IdentityPublicKey":
                outcome.string = try SymvaultFFI.identityPublicKey(identity: s(args, "identity"))
            case "PublicKeyFingerprint":
                outcome.string = try SymvaultFFI.publicKeyFingerprint(pubkey: s(args, "pubkey"))
            case "EncryptWithPublicKey":
                outcome.bytes = try SymvaultFFI.encryptWithPublicKey(
                    recipient: s(args, "recipient"), plaintext: plaintext(args))
            case "DecryptWithIdentity":
                outcome.bytes = try SymvaultFFI.decryptWithIdentity(
                    identity: s(args, "identity"), ciphertext: ciphertext(args, seed))
            case "EncryptWithPassphrase":
                outcome.bytes = try SymvaultFFI.encryptWithPassphrase(
                    passphrase: s(args, "passphrase"), plaintext: plaintext(args))
            case "DecryptWithPassphrase":
                outcome.bytes = try SymvaultFFI.decryptWithPassphrase(
                    passphrase: s(args, "passphrase"), ciphertext: ciphertext(args, seed))
            case "InitVault":
                try SymvaultFFI.initVault(
                    vaultDir: s(args, "vaultDir"), passphrase: s(args, "passphrase"))
            case "OpenVaultWithPassphrase":
                outcome.string = try SymvaultFFI.openVaultWithPassphrase(
                    vaultDir: s(args, "vaultDir"), passphrase: s(args, "passphrase"))
            case "ReadEntryJSON":
                outcome.string = try SymvaultFFI.readEntryJSON(
                    vaultDir: s(args, "vaultDir"), entryPath: s(args, "entryPath"),
                    identity: s(args, "identity"))
            case "WriteEntryJSON":
                try SymvaultFFI.writeEntryJSON(
                    vaultDir: s(args, "vaultDir"), entryPath: s(args, "entryPath"),
                    entryJSON: entryJSON(args), identity: s(args, "identity"))
            case "ListEntriesJSON":
                outcome.string = try SymvaultFFI.listEntriesJSON(
                    vaultDir: s(args, "vaultDir"), prefix: s(args, "prefix"),
                    identity: s(args, "identity"))
            case "VerifyManifestIntegrity":
                outcome.flag = try SymvaultFFI.verifyManifestIntegrity(
                    vaultDir: s(args, "vaultDir"), identity: s(args, "identity"))
            default:
                XCTFail("unknown function \(function)")
            }
            outcome.ok = true
        } catch let error as SymvaultFFIError {
            outcome.ok = false
            outcome.error = error.description
            if case .go = error {} else { XCTFail("\(function): boundary failure \(error)") }
        } catch {
            XCTFail("\(function): \(error)")
        }
        return outcome
    }

    // MARK: normalization (identical to the Go generator and the Rust replay)

    func normalizePaths(_ text: String, _ root: String) -> String {
        text.replacingOccurrences(of: "/private" + root, with: "$ROOT")
            .replacingOccurrences(of: root, with: "$ROOT")
    }

    func isRFC3339UTC(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard bytes.count >= 20, value.hasSuffix("Z") else { return false }
        let shape = Array("dddd-dd-ddTdd:dd:dd".utf8)
        for (index, kind) in shape.enumerated() {
            if kind == UInt8(ascii: "d") {
                if !(UInt8(ascii: "0")...UInt8(ascii: "9")).contains(bytes[index]) { return false }
            } else if bytes[index] != kind {
                return false
            }
        }
        let tail = Array(bytes[19..<(bytes.count - 1)])
        if tail.isEmpty { return true }
        return tail[0] == UInt8(ascii: ".") && (2...10).contains(tail.count)
            && tail.dropFirst().allSatisfy { (UInt8(ascii: "0")...UInt8(ascii: "9")).contains($0) }
    }

    func normalizeTimestamps(_ text: String) -> String {
        guard let object = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? JSON,
            let meta = object["meta"] as? JSON
        else { return text }
        var result = text
        for key in ["created", "updated"] {
            if let value = meta[key] as? String, isRFC3339UTC(value),
                let range = result.range(of: "\"\(key)\":\"\(value)\"")
            {
                result.replaceSubrange(range, with: "\"\(key)\":\"<TIMESTAMP>\"")
            }
        }
        return result
    }

    func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    // MARK: checks

    func charsetOK(_ body: Substring, _ charset: String) -> Bool {
        switch charset {
        case "bech32-upper": return body.utf8.allSatisfy { ($0 >= 65 && $0 <= 90) || ($0 >= 48 && $0 <= 57) }
        case "bech32-lower": return body.utf8.allSatisfy { ($0 >= 97 && $0 <= 122) || ($0 >= 48 && $0 <= 57) }
        default: return true
        }
    }

    /// rust-age appends one random `*-grease` stanza to X25519 headers that
    /// Go's age does not write (8...200 extra bytes, identical payload).
    func greasePresent(_ data: Data) -> Bool {
        let head = String(decoding: data.prefix(600), as: UTF8.self)
        let end = head.range(of: "\n--- ")?.lowerBound ?? head.endIndex
        let count = head[..<end].split(separator: "\n").filter { line in
            line.hasPrefix("-> ") && (line.dropFirst(3).split(separator: " ").first?.hasSuffix("-grease") ?? false)
        }.count
        return count == 1
    }

    func checkShape(_ outcome: Outcome, _ shape: JSON) -> String? {
        if !outcome.ok { return "unexpected error: \(outcome.error)" }
        let length = shape["length"] as? Int ?? 0
        if let text = outcome.string {
            let prefix = shape["string_prefix"] as? String ?? ""
            if !text.hasPrefix(prefix) || text.utf8.count != length {
                return "string shape mismatch: \(text.utf8.count) bytes, prefix \(prefix)"
            }
            let body = text.dropFirst(prefix.count)
            if !charsetOK(body, shape["string_charset"] as? String ?? "") { return "charset mismatch" }
        }
        if let data = outcome.bytes {
            let prefix = Data(base64Encoded: shape["bytes_prefix_b64"] as? String ?? "") ?? Data()
            if !data.starts(with: prefix) { return "bytes prefix mismatch" }
            if data.count != length {
                let x25519 = data.starts(with: Data("age-encryption.org/v1\n-> X25519 ".utf8))
                if !(x25519 && (length + 1...length + 200).contains(data.count) && greasePresent(data)) {
                    return "bytes shape mismatch: \(data.count) bytes, want \(length)"
                }
            }
            if let factor = shape["scrypt_work_factor"] as? Int {
                let header = String(decoding: data.prefix(200), as: UTF8.self)
                let lines = header.split(separator: "\n", omittingEmptySubsequences: false)
                let line = lines.count > 1 ? String(lines[1]) : ""
                if !line.hasSuffix(" \(factor)") { return "scrypt stanza \(line) lacks work factor \(factor)" }
            }
        }
        return nil
    }

    func checkExact(_ outcome: Outcome, _ want: JSON, _ root: String, _ normalize: [String]) -> String? {
        let wantsOK = want["ok"] as? Bool ?? false
        if outcome.ok != wantsOK {
            return "ok=\(outcome.ok) but fixture ok=\(wantsOK); error \(outcome.error); want \(want["error"] ?? "")"
        }
        if !wantsOK {
            let got = normalizePaths(outcome.error, root)
            let expected = want["error"] as? String ?? ""
            return got == expected ? nil : "error text differs:\n   got: \(got)\n  want: \(expected)"
        }
        if let expected = want["string"] as? String {
            var got = normalizePaths(outcome.string ?? "<none>", root)
            if normalize.contains("timestamps") { got = normalizeTimestamps(got) }
            if got != expected { return "string differs:\n   got: \(got)\n  want: \(expected)" }
        }
        if let expected = want["bytes_b64"] as? String {
            if outcome.bytes != Data(base64Encoded: expected) { return "bytes differ" }
        }
        if let length = want["bytes_len"] as? Int {
            let data = outcome.bytes ?? Data()
            if data.count != length || sha256Hex(data) != (want["bytes_sha256"] as? String ?? "") {
                return "large bytes differ (length or sha256)"
            }
        }
        if let expected = want["bool"] as? Bool, outcome.flag != expected {
            return "bool \(String(describing: outcome.flag)), want \(expected)"
        }
        return nil
    }

    func substituteOut(_ args: JSON, _ produced: Outcome) -> JSON {
        var args = args
        for key in ["identity", "recipient", "pubkey"] where (args[key] as? String) == "$OUT" {
            args[key] = produced.string ?? ""
        }
        if (args["ciphertext_b64"] as? String) == "$OUT" {
            args["ciphertext_b64"] = (produced.bytes ?? Data()).base64EncodedString()
        }
        return args
    }

    func expandRoot(_ args: JSON, _ root: String) -> JSON {
        var args = args
        if let dir = args["vaultDir"] as? String {
            args["vaultDir"] = dir.replacingOccurrences(of: "$ROOT", with: root)
        }
        return args
    }

    /// Runs one step; returns the mismatch against the fixture (nil = matches Go)
    /// together with the outcome Rust produced.
    func runStep(_ step: JSON, _ seed: JSON, _ root: String) -> (String?, Outcome) {
        let function = step["function"] as? String ?? ""
        let args = expandRoot(step["args"] as? JSON ?? [:], root)
        let outcome = call(function, args, seed)
        return (verdict(step, function, args, outcome, seed, root), outcome)
    }

    func verdict(_ step: JSON, _ function: String, _ args: JSON, _ outcome: Outcome, _ seed: JSON, _ root: String)
        -> String?
    {
        let normalize = step["normalize"] as? [String] ?? []
        let want = step["want"] as? JSON ?? [:]
        if let shape = want["shape"] as? JSON {
            if let problem = checkShape(outcome, shape) { return problem }
            if shape["distinct_across_calls"] as? Bool == true {
                let again = call(function, args, seed)
                if again.bytes == outcome.bytes && again.string == outcome.string {
                    return "two calls produced identical output"
                }
            }
            if let roundtrip = shape["roundtrip"] as? JSON {
                let rtFunction = roundtrip["function"] as? String ?? ""
                let rtArgs = expandRoot(
                    substituteOut(roundtrip["args"] as? JSON ?? [:], outcome), root)
                let rtOutcome = call(rtFunction, rtArgs, seed)
                let rtWant = roundtrip["want"] as? JSON ?? [:]
                if let rtShape = rtWant["shape"] as? JSON {
                    if let problem = checkShape(rtOutcome, rtShape) { return "roundtrip: \(problem)" }
                } else if let problem = checkExact(rtOutcome, rtWant, root, []) {
                    return "roundtrip \(rtFunction): \(problem)"
                }
            }
            return nil
        }
        return checkExact(outcome, want, root, normalize)
    }

    // MARK: vault tree
    //
    // Foundation URLs decompose "é" to "e" + U+0301 when a path is created,
    // while Go and Rust write the bytes they are given. Everything that creates
    // names therefore uses POSIX calls with the raw UTF-8 bytes.

    func chmodRaw(_ path: String, _ mode: Int) { _ = chmod(path, mode_t(mode)) }

    func mkdirAll(_ path: String, mode: Int = 0o755) {
        var current = ""
        for component in path.split(separator: "/", omittingEmptySubsequences: true) {
            current += "/" + component
            _ = mkdir(current, mode_t(mode))
        }
    }

    func parent(_ path: String) -> String {
        guard let slash = path.lastIndex(of: "/") else { return "." }
        return String(path[..<slash])
    }

    func writeRaw(_ path: String, _ data: Data) throws {
        let fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0o600)
        guard fd >= 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
        defer { close(fd) }
        try data.withUnsafeBytes { raw in
            var offset = 0
            while offset < raw.count {
                let written = write(fd, raw.baseAddress! + offset, raw.count - offset)
                guard written > 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
                offset += written
            }
        }
    }

    func materialize(_ files: [JSON], _ directory: String, _ root: String) throws {
        mkdirAll(directory)
        for file in files {
            let target = directory + "/" + (file["path"] as? String ?? "")
            let mode = file["mode"] as? Int ?? 0o600
            if file["dir"] as? Bool == true {
                mkdirAll(target)
                chmodRaw(target, mode)
                continue
            }
            mkdirAll(parent(target))
            var data = Data(base64Encoded: file["b64"] as? String ?? "") ?? Data()
            if let text = String(data: data, encoding: .utf8) {
                data = Data(text.replacingOccurrences(of: "$ROOT", with: root).utf8)
            }
            try writeRaw(target, data)
            chmodRaw(target, mode)
        }
    }

    func mutate(_ vault: String, _ mutation: JSON) throws {
        let fm = FileManager.default
        let target = vault + "/" + (mutation["path"] as? String ?? "")
        switch mutation["op"] as? String ?? "" {
        case "remove":
            try? fm.removeItem(atPath: target)
        case "write":
            mkdirAll(parent(target))
            let encoded = mutation["b64"] as? String ?? ""
            let data =
                encoded.isEmpty
                ? Data((mutation["text"] as? String ?? "").utf8)
                : (Data(base64Encoded: encoded) ?? Data())
            try writeRaw(target, data)
        case "flip":
            var data = try Data(contentsOf: URL(fileURLWithPath: target))
            data[mutation["offset"] as? Int ?? 0] ^= 0x01
            try writeRaw(target, data)
        case "truncate":
            XCTAssertEqual(truncate(target, off_t(mutation["size"] as? Int ?? 0)), 0)
        case "mkdir":
            mkdirAll(target)
        case "symlink":
            try? fm.removeItem(atPath: target)
            XCTAssertEqual(symlink(mutation["target"] as? String ?? "", target), 0)
        case "rename":
            let destination = vault + "/" + (mutation["target"] as? String ?? "")
            XCTAssertEqual(rename(target, destination), 0)
        default:
            XCTFail("unknown mutation \(mutation)")
        }
    }

    func collect(_ base: String, _ directory: String, _ out: inout [String]) {
        let fm = FileManager.default
        for name in (try? fm.contentsOfDirectory(atPath: directory)) ?? [] {
            // Lock and cache files are implementation detail, as in the Go snapshot.
            if name == ".lock" || name == ".search-index" { continue }
            let path = directory + "/" + name
            out.append(String(path.dropFirst(base.count + 1)))
            var isDirectory: ObjCBool = false
            if fm.fileExists(atPath: path, isDirectory: &isDirectory), isDirectory.boolValue {
                collect(base, path, &out)
            }
        }
    }

    func checkAfter(_ after: JSON, _ base: String, _ root: String) -> String? {
        let fm = FileManager.default
        if let tree = after["tree"] as? [String] {
            var actual: [String] = []
            collect(base, base, &actual)
            // Declared D1 difference: Rust vaults carry the `.symvault-rust`
            // marker (the Rust replay drops it the same way).
            actual.removeAll { $0 == ".symvault-rust" }
            let byBytes: ([String]) -> [String] = { $0.sorted { Array($0.utf8).lexicographicallyPrecedes(Array($1.utf8)) } }
            if byBytes(actual) != tree { return "tree \(byBytes(actual)), want \(tree)" }
        }
        if let files = after["files"] as? [String: JSON] {
            for (name, state) in files {
                let path = base + "/" + name
                var isDirectory: ObjCBool = false
                guard fm.fileExists(atPath: path, isDirectory: &isDirectory) else {
                    return "\(name): missing"
                }
                if isDirectory.boolValue != (state["dir"] as? Bool ?? false) {
                    return "\(name): directory flag differs"
                }
                let attributes = try? fm.attributesOfItem(atPath: path)
                let mode = ((attributes?[.posixPermissions] as? Int) ?? -1) & 0o777
                if mode != (state["mode"] as? Int ?? 0) { return "\(name): mode \(String(mode, radix: 8))" }
                if let text = state["text"] as? String {
                    let got = normalizePaths(
                        (try? String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)) ?? "<unreadable>", root)
                    if got != text { return "\(name) text differs:\n   got: \(got)\n  want: \(text)" }
                }
            }
        }
        return nil
    }

    // MARK: the replay

    func testReplaysEveryRecordedCaseThroughSwiftAndRust() throws {
        XCTAssertEqual(SymvaultFFI.abiVersion, 1)
        let fixture = try Self.loadJSON("mobilebind.json")
        let divergences = try Self.loadJSON("known-divergences.json")
        let known = Dictionary(
            uniqueKeysWithValues: (divergences["cases"] as? [JSON] ?? []).map {
                ($0["id"] as? String ?? "", ($0["reason"] as? String ?? "", $0["expected_rust"] as? String))
            })
        let seed = try XCTUnwrap(fixture["seed"] as? JSON)
        let files = try XCTUnwrap((seed["vault"] as? JSON)?["files"] as? [JSON])
        let cases = try XCTUnwrap(fixture["cases"] as? [JSON])

        // The seed vaults carry no `.symvault-rust` marker, so the data-safety
        // gate (decision D1) backs each one up before its first mutation. Send
        // those backups to a throw-away directory through the host API, never
        // to the developer's state directory.
        let backupRoot = FileManager.default.temporaryDirectory.path
            + "/symvault-ffi-backups-\(UUID().uuidString)"
        try SymvaultFFI.setBackupDir(backupRoot)
        defer {
            try? SymvaultFFI.setBackupDir("")
            try? FileManager.default.removeItem(atPath: backupRoot)
        }

        var counts: [String: Int] = [:]
        var failures: [String] = []
        let fm = FileManager.default
        for testCase in cases {
            let id = testCase["id"] as? String ?? ""
            let root = fm.temporaryDirectory.path + "/symvault-ffi-\(UUID().uuidString)"
            mkdirAll(root)
            defer { try? fm.removeItem(atPath: root) }
            let vault = root + "/vault"
            if testCase["vault"] as? Bool == true { try materialize(files, vault, root) }
            for mutation in testCase["mutations"] as? [JSON] ?? [] { try mutate(vault, mutation) }
            let steps = testCase["steps"] as? [JSON] ?? []
            for (index, step) in steps.enumerated() {
                let function = step["function"] as? String ?? ""
                counts[function, default: 0] += 1
                let (problem, outcome) = runStep(step, seed, root)
                if let (reason, expectedRust) = known[id] {
                    // A recorded divergence must still differ from Go, and Rust's
                    // answer must be exactly `expected_rust`: an entry cannot hide
                    // a different failure.
                    if problem == nil {
                        failures.append("\(id): listed in known-divergences.json but now matches Go; remove the entry")
                    } else {
                        let actual = normalizePaths(outcome.error, root)
                        if outcome.ok || expectedRust == nil || actual != expectedRust! {
                            failures.append(
                                "\(id) step \(index): known divergence (\(reason)) must return exactly \(String(describing: expectedRust)), got ok=\(outcome.ok) \(actual)")
                        }
                    }
                } else if let problem {
                    failures.append("\(id) step \(index) (\(function)): \(problem)")
                }
            }
            if let after = testCase["after"] as? JSON {
                let first = expandRoot((steps.first?["args"] as? JSON) ?? [:], root)
                if let problem = checkAfter(after, first["vaultDir"] as? String ?? "", root) {
                    failures.append("\(id) after-state: \(problem)")
                }
            }
        }

        let recorded = fixture["step_counts"] as? [String: Int] ?? [:]
        var total = 0
        for function in Self.functions {
            let replayed = counts[function] ?? 0
            total += replayed
            print("FFI-001 swift \(function.padding(toLength: 26, withPad: " ", startingAt: 0)) \(replayed) steps")
            XCTAssertGreaterThan(replayed, 0, "\(function) was not exercised")
            XCTAssertEqual(replayed, recorded[function], "\(function): step count differs from fixture")
        }
        print("FFI-001 swift replayed \(total) steps over \(cases.count) cases")
        for failure in failures.prefix(40) { print("MISMATCH \(failure)") }
        XCTAssertTrue(failures.isEmpty, "\(failures.count) of \(total) steps differ from the Go oracle")
    }

    func testBinaryAndErrorSurfaceOfTheWrapper() throws {
        let secret = try SymvaultFFI.generateIdentity()
        XCTAssertTrue(secret.hasPrefix("AGE-SECRET-KEY-1"))
        let recipient = try SymvaultFFI.identityPublicKey(identity: secret)
        let message = Data((0..<70_000).map { UInt8($0 % 251) })
        let sealed = try SymvaultFFI.encryptWithPublicKey(recipient: recipient, plaintext: message)
        XCTAssertEqual(try SymvaultFFI.decryptWithIdentity(identity: secret, ciphertext: sealed), message)
        XCTAssertThrowsError(try SymvaultFFI.identityPublicKey(identity: "nope")) { error in
            guard case SymvaultFFIError.go(let text) = error else { return XCTFail("\(error)") }
            XCTAssertTrue(text.hasPrefix("validate identity: "), text)
        }
        XCTAssertThrowsError(try SymvaultFFI.encryptWithPassphrase(passphrase: "", plaintext: message)) {
            XCTAssertEqual($0 as? SymvaultFFIError, .go("passphrase is empty"))
        }
    }
}
