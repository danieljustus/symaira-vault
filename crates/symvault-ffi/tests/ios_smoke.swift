import Darwin
import Foundation
import SymvaultRustCore
import UIKit

enum SmokeFailure: Error, CustomStringConvertible {
  case contract(String)
  case ffi(String)
  case fixture(String)

  var description: String {
    switch self {
    case .contract(let message), .ffi(let message), .fixture(let message): message
    }
  }
}

func take(_ buffer: SymvaultBuffer) -> Data {
  defer { symvault_buffer_free(buffer) }
  guard buffer.len > 0, let pointer = buffer.data else { return Data() }
  return Data(bytes: pointer, count: buffer.len)
}

func output(_ result: SymvaultResult) throws -> Data {
  let error = take(result.error)
  guard error.isEmpty else {
    _ = take(result.output)
    throw SmokeFailure.ffi(String(decoding: error, as: UTF8.self))
  }
  return take(result.output)
}

func fixture(_ name: String) throws -> [String: Any] {
  let url = Bundle.main.bundleURL
    .appendingPathComponent("Fixtures", isDirectory: true)
    .appendingPathComponent(name)
  let bytes: Data
  do {
    bytes = try Data(contentsOf: url)
  } catch {
    throw SmokeFailure.fixture("cannot read bundled \(name): \(error)")
  }
  guard let value = try JSONSerialization.jsonObject(with: bytes) as? [String: Any] else {
    throw SmokeFailure.fixture("bundled \(name) is not a JSON object")
  }
  return value
}

func decrypt(_ ciphertext: Data, with identity: String) throws -> Data {
  let identityBytes = Data(identity.utf8)
  return try identityBytes.withUnsafeBytes { identityRaw in
    try ciphertext.withUnsafeBytes { ciphertextRaw in
      try output(
        symvault_decrypt_with_identity(
          identityRaw.bindMemory(to: UInt8.self).baseAddress,
          identityBytes.count,
          ciphertextRaw.bindMemory(to: UInt8.self).baseAddress,
          ciphertext.count
        ))
    }
  }
}

func decrypt(_ ciphertext: Data, withPassphrase passphrase: String) throws -> Data {
  let passphraseBytes = Data(passphrase.utf8)
  return try passphraseBytes.withUnsafeBytes { passphraseRaw in
    try ciphertext.withUnsafeBytes { ciphertextRaw in
      try output(
        symvault_decrypt_with_passphrase(
          passphraseRaw.bindMemory(to: UInt8.self).baseAddress,
          passphraseBytes.count,
          ciphertextRaw.bindMemory(to: UInt8.self).baseAddress,
          ciphertext.count
        ))
    }
  }
}

func verifyCryptoFixture() throws -> String {
  let crypto = try fixture("age-kdf.json")
  guard
    let identities = crypto["identities"] as? [[String: Any]],
    let cases = crypto["age_cases"] as? [[String: Any]],
    cases.count == 2
  else {
    throw SmokeFailure.fixture("Go age fixture is missing its recipient cases")
  }

  for testCase in cases {
    guard
      let plaintext = testCase["plaintext"] as? String,
      let encodedCiphertext = testCase["ciphertext"] as? String,
      let ciphertext = Data(base64Encoded: encodedCiphertext),
      let recipients = testCase["recipients"] as? [String],
      !recipients.isEmpty
    else {
      throw SmokeFailure.fixture("Go age fixture case has invalid fields")
    }
    let recipientNames = Set(recipients)
    let matchingIdentities = identities.filter {
      guard let recipient = $0["recipient"] as? String else { return false }
      return recipientNames.contains(recipient)
    }
    guard matchingIdentities.count == recipientNames.count else {
      throw SmokeFailure.fixture("Go age fixture has no identity for every recipient")
    }
    for identity in matchingIdentities {
      guard let secret = identity["identity"] as? String else {
        throw SmokeFailure.fixture("Go age fixture identity has no secret string")
      }
      guard try decrypt(ciphertext, with: secret) == Data(plaintext.utf8) else {
        throw SmokeFailure.contract("Rust FFI did not decrypt a Go age fixture recipient")
      }
    }
  }
  guard
    let scryptCases = crypto["scrypt_cases"] as? [[String: Any]],
    let scryptCase = scryptCases.first(where: { $0["name"] as? String == "legacy_work_factor_12" }),
    let scryptPlaintext = scryptCase["plaintext"] as? String,
    let encodedScrypt = scryptCase["ciphertext"] as? String,
    let scryptCiphertext = Data(base64Encoded: encodedScrypt)
  else {
    throw SmokeFailure.fixture("Go crypto fixture is missing legacy scrypt fields")
  }
  guard
    try decrypt(scryptCiphertext, withPassphrase: "rust-interop-fixture-passphrase-v1")
      == Data(scryptPlaintext.utf8)
  else {
    throw SmokeFailure.contract("Rust FFI did not decrypt the Go scrypt fixture")
  }
  guard let reencryptCases = crypto["reencrypt_cases"] as? [[String: Any]],
    reencryptCases.count == 2
  else {
    throw SmokeFailure.fixture("Go crypto fixture is missing its re-encryption cases")
  }
  for testCase in reencryptCases {
    guard
      let plaintext = testCase["plaintext"] as? String,
      let encodedCiphertext = testCase["reencrypted_ciphertext"] as? String,
      let ciphertext = Data(base64Encoded: encodedCiphertext),
      let recipients = testCase["recipients"] as? [String],
      let removedIdentity = testCase["removed_identity"] as? String
    else {
      throw SmokeFailure.fixture("Go re-encryption fixture case has invalid fields")
    }
    let recipientNames = Set(recipients)
    let retained = identities.filter { recipientNames.contains($0["recipient"] as? String ?? "") }
    guard retained.count == recipientNames.count else {
      throw SmokeFailure.fixture("Go re-encryption fixture has no identity for every recipient")
    }
    for identity in retained {
      guard let secret = identity["identity"] as? String else {
        throw SmokeFailure.fixture("Go re-encryption fixture identity has no secret string")
      }
      guard try decrypt(ciphertext, with: secret) == Data(plaintext.utf8) else {
        throw SmokeFailure.contract("Rust FFI did not decrypt a retained Go recipient")
      }
    }
    guard (try? decrypt(ciphertext, with: removedIdentity)) == nil else {
      throw SmokeFailure.contract("Rust FFI decrypted a removed Go recipient")
    }
  }
  guard let storeIdentity = identities.first?["identity"] as? String else {
    throw SmokeFailure.fixture("Go age fixture has no store identity")
  }
  return storeIdentity
}

func callRead(vault: URL, entry: String, identity: String) throws -> Data {
  let vaultBytes = Data(vault.path.utf8)
  let entryBytes = Data(entry.utf8)
  let identityBytes = Data(identity.utf8)
  return try vaultBytes.withUnsafeBytes { vaultRaw in
    try entryBytes.withUnsafeBytes { entryRaw in
      try identityBytes.withUnsafeBytes { identityRaw in
        try output(
          symvault_read_entry_json(
            vaultRaw.bindMemory(to: UInt8.self).baseAddress,
            vaultBytes.count,
            entryRaw.bindMemory(to: UInt8.self).baseAddress,
            entryBytes.count,
            identityRaw.bindMemory(to: UInt8.self).baseAddress,
            identityBytes.count
          ))
      }
    }
  }
}

func callWrite(vault: URL, entry: String, json: String, identity: String) throws -> Data {
  let vaultBytes = Data(vault.path.utf8)
  let entryBytes = Data(entry.utf8)
  let jsonBytes = Data(json.utf8)
  let identityBytes = Data(identity.utf8)
  return try vaultBytes.withUnsafeBytes { vaultRaw in
    try entryBytes.withUnsafeBytes { entryRaw in
      try jsonBytes.withUnsafeBytes { jsonRaw in
        try identityBytes.withUnsafeBytes { identityRaw in
          try output(
            symvault_write_entry_json(
              vaultRaw.bindMemory(to: UInt8.self).baseAddress,
              vaultBytes.count,
              entryRaw.bindMemory(to: UInt8.self).baseAddress,
              entryBytes.count,
              jsonRaw.bindMemory(to: UInt8.self).baseAddress,
              jsonBytes.count,
              identityRaw.bindMemory(to: UInt8.self).baseAddress,
              identityBytes.count
            ))
        }
      }
    }
  }
}

func callList(vault: URL, prefix: String, identity: String) throws -> Data {
  let vaultBytes = Data(vault.path.utf8)
  let prefixBytes = Data(prefix.utf8)
  let identityBytes = Data(identity.utf8)
  return try vaultBytes.withUnsafeBytes { vaultRaw in
    try prefixBytes.withUnsafeBytes { prefixRaw in
      try identityBytes.withUnsafeBytes { identityRaw in
        try output(
          symvault_list_entries_json(
            vaultRaw.bindMemory(to: UInt8.self).baseAddress,
            vaultBytes.count,
            prefixRaw.bindMemory(to: UInt8.self).baseAddress,
            prefixBytes.count,
            identityRaw.bindMemory(to: UInt8.self).baseAddress,
            identityBytes.count
          ))
      }
    }
  }
}

func callManifest(vault: URL, identity: String) throws -> Data {
  let vaultBytes = Data(vault.path.utf8)
  let identityBytes = Data(identity.utf8)
  return try vaultBytes.withUnsafeBytes { vaultRaw in
    try identityBytes.withUnsafeBytes { identityRaw in
      try output(
        symvault_verify_manifest_integrity(
          vaultRaw.bindMemory(to: UInt8.self).baseAddress,
          vaultBytes.count,
          identityRaw.bindMemory(to: UInt8.self).baseAddress,
          identityBytes.count
        ))
    }
  }
}

func fixtureFileURL(root: URL, relativePath: String) throws -> URL {
  guard !relativePath.hasPrefix("/"), !relativePath.split(separator: "/").contains("..") else {
    throw SmokeFailure.fixture("store fixture contains an unsafe path")
  }
  return root.appendingPathComponent(relativePath)
}

func verifyStoreFixture(identity: String) throws {
  let storeFixture = try fixture("store.json")
  guard
    let vaults = storeFixture["vaults"] as? [[String: Any]],
    let vault = vaults.first,
    let migration = vault["migration"] as? [String: Any],
    let after = migration["after"] as? [String: Any],
    let files = after["files"] as? [[String: Any]],
    let entries = vault["entries"] as? [[String: Any]]
  else {
    throw SmokeFailure.fixture("Go store fixture is missing its replay files")
  }

  let root = FileManager.default.temporaryDirectory
    .appendingPathComponent("symvault-ios-store-\(UUID().uuidString)", isDirectory: true)
  try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
  defer { try? FileManager.default.removeItem(at: root) }

  for file in files {
    guard
      let relativePath = file["path"] as? String,
      let content = file["content"] as? String,
      let bytes = Data(base64Encoded: content)
    else {
      throw SmokeFailure.fixture("Go store fixture file has invalid path or content")
    }
    let destination = try fixtureFileURL(root: root, relativePath: relativePath)
    try FileManager.default.createDirectory(
      at: destination.deletingLastPathComponent(),
      withIntermediateDirectories: true
    )
    try bytes.write(to: destination)
  }

  for entry in entries {
    guard
      let path = entry["path"] as? String,
      let expectedJSON = entry["expected_json"] as? String,
      try callRead(vault: root, entry: path, identity: identity) == Data(expectedJSON.utf8)
    else {
      throw SmokeFailure.contract("Rust FFI read JSON differs from Go store fixture")
    }
  }

  let prefix = "nested/"
  let expectedPaths = entries.compactMap { $0["path"] as? String }
    .filter { $0.hasPrefix(prefix) }
    .sorted()
  let expectedList = Data(
    ("[" + expectedPaths.map { "\"\($0)\"" }.joined(separator: ",") + "]").utf8)
  guard try callList(vault: root, prefix: prefix, identity: identity) == expectedList else {
    throw SmokeFailure.contract("Rust FFI list differs from Go store fixture paths")
  }
  guard try callManifest(vault: root, identity: identity) == Data([1]) else {
    throw SmokeFailure.contract("Rust FFI rejected the intact Go store manifest")
  }

  let newPath = "nested/ios-write"
  guard
    try callWrite(
      vault: root, entry: newPath, json: #"{"data":{"username":"ios-fixture"}}"#,
      identity: identity).isEmpty
  else {
    throw SmokeFailure.contract("Rust FFI writer returned data for a successful write")
  }
  let written = try JSONSerialization.jsonObject(
    with: callRead(vault: root, entry: newPath, identity: identity)) as? [String: Any]
  let data = written?["data"] as? [String: Any]
  guard data?["username"] as? String == "ios-fixture" else {
    throw SmokeFailure.contract("Rust FFI did not read back its encrypted iOS write")
  }
  guard try callManifest(vault: root, identity: identity) == Data([1]) else {
    throw SmokeFailure.contract("Rust FFI write left the Go store manifest invalid")
  }

  let tamperedEntry = try fixtureFileURL(root: root, relativePath: "entries/minimal.age")
  try Data("tampered".utf8).write(to: tamperedEntry, options: .atomic)
  guard try callManifest(vault: root, identity: identity) == Data([0]) else {
    throw SmokeFailure.contract("Rust FFI accepted a tampered Go store entry")
  }
}

func runContracts() throws {
  let identity = try verifyCryptoFixture()
  try verifyStoreFixture(identity: identity)
}

@MainActor @objc final class RustCoreSmokeAppDelegate: UIResponder, UIApplicationDelegate {
  func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
  ) -> Bool {
    do {
      try runContracts()
      let marker = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        .appendingPathComponent("rust-ffi-smoke.pass")
      try Data("go-fixture-contracts-ok\n".utf8).write(to: marker, options: .atomic)
      exit(0)
    } catch {
      fputs("iOS Rust FFI contract smoke failed: \(error)\n", stderr)
      exit(1)
    }
  }
}

UIApplicationMain(
  CommandLine.argc,
  CommandLine.unsafeArgv,
  nil,
  NSStringFromClass(RustCoreSmokeAppDelegate.self)
)
