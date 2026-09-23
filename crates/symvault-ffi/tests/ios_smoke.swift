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

func decrypt(_ ciphertext: Data, withPassphrase passphrase: String, argon2id: Bool = false)
  throws -> Data
{
  let passphraseBytes = Data(passphrase.utf8)
  return try passphraseBytes.withUnsafeBytes { passphraseRaw in
    try ciphertext.withUnsafeBytes { ciphertextRaw in
      let passphrasePointer = passphraseRaw.bindMemory(to: UInt8.self).baseAddress
      let ciphertextPointer = ciphertextRaw.bindMemory(to: UInt8.self).baseAddress
      let result = if argon2id {
        symvault_decrypt_with_passphrase_argon2id(
          passphrasePointer, passphraseBytes.count,
          ciphertextPointer, ciphertext.count
        )
      } else {
        symvault_decrypt_with_passphrase(
          passphrasePointer, passphraseBytes.count,
          ciphertextPointer, ciphertext.count
        )
      }
      return try output(result)
    }
  }
}

func callVault(_ vault: URL, passphrase: String, initialize: Bool) throws -> Data {
  let path = Data(vault.path.utf8)
  let secret = Data(passphrase.utf8)
  return try path.withUnsafeBytes { pathRaw in
    try secret.withUnsafeBytes { secretRaw in
      let pathPointer = pathRaw.bindMemory(to: UInt8.self).baseAddress
      let secretPointer = secretRaw.bindMemory(to: UInt8.self).baseAddress
      let result = if initialize {
        symvault_init_vault(pathPointer, path.count, secretPointer, secret.count)
      } else {
        symvault_open_vault_with_passphrase(pathPointer, path.count, secretPointer, secret.count)
      }
      return try output(result)
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
  guard
    let argonCases = crypto["argon2id_cases"] as? [[String: Any]],
    let argonCase = argonCases.first(where: { $0["name"] as? String == "current_tiny_fixture_params" }),
    let argonPlaintext = argonCase["plaintext"] as? String,
    let encodedArgon = argonCase["ciphertext"] as? String,
    let argonCiphertext = Data(base64Encoded: encodedArgon)
  else {
    throw SmokeFailure.fixture("Go crypto fixture is missing Argon2id fields")
  }
  guard
    try decrypt(argonCiphertext, withPassphrase: "rust-interop-fixture-passphrase-v1", argon2id: true)
      == Data(argonPlaintext.utf8)
  else {
    throw SmokeFailure.contract("Rust FFI did not decrypt the Go Argon2id fixture")
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

func verifyMobileVaultFixture() throws {
  let mobile = try fixture("go-mobile-vault.json")
  guard
    let passphrase = mobile["passphrase"] as? String,
    let identity = mobile["identity"] as? String,
    let encoded = mobile["identity_age_base64"] as? String,
    let encrypted = Data(base64Encoded: encoded)
  else {
    throw SmokeFailure.fixture("Go mobile fixture is incomplete")
  }
  let root = FileManager.default.temporaryDirectory
    .appendingPathComponent("symvault-ios-mobile-\(UUID().uuidString)", isDirectory: true)
  defer { try? FileManager.default.removeItem(at: root) }
  let goVault = root.appendingPathComponent("go-vault", isDirectory: true)
  try FileManager.default.createDirectory(
    at: goVault.appendingPathComponent("entries", isDirectory: true),
    withIntermediateDirectories: true)
  let quotedBytes = try JSONSerialization.data(
    withJSONObject: goVault.path, options: .fragmentsAllowed)
  guard let quotedPath = String(data: quotedBytes, encoding: .utf8) else {
    throw SmokeFailure.fixture("Go mobile vault path is not UTF-8")
  }
  try Data("vaultDir: \(quotedPath)\nvault:\n  format_version: 2\n".utf8)
    .write(to: goVault.appendingPathComponent("config.yaml"))
  try encrypted.write(to: goVault.appendingPathComponent("identity.age"))
  guard try callVault(goVault, passphrase: passphrase, initialize: false) == Data(identity.utf8) else {
    throw SmokeFailure.contract("Rust FFI did not open the Go mobile vault")
  }

  let newVault = root.appendingPathComponent("rust-vault", isDirectory: true)
  guard try callVault(newVault, passphrase: passphrase, initialize: true).isEmpty else {
    throw SmokeFailure.contract("Rust FFI init returned data")
  }
  let opened = try callVault(newVault, passphrase: passphrase, initialize: false)
  guard String(decoding: opened, as: UTF8.self).hasPrefix("AGE-SECRET-KEY-1") else {
    throw SmokeFailure.contract("Rust FFI did not reopen its initialized vault")
  }
  guard (try? callVault(newVault, passphrase: "wrong passphrase", initialize: false)) == nil else {
    throw SmokeFailure.contract("Rust FFI opened a vault with the wrong passphrase")
  }
}

func verifyZeroKeyRecovery() throws {
  let crypto = try fixture("age-kdf.json")
  guard
    let zeroCase = (crypto["zero_key_cases"] as? [[String: Any]])?.first,
    let encoded = zeroCase["ciphertext"] as? String,
    let encrypted = Data(base64Encoded: encoded),
    let passphraseLength = zeroCase["passphrase_length"] as? Int,
    let recipient = zeroCase["expected_recipient"] as? String,
    let identities = crypto["identities"] as? [[String: Any]],
    let identity = identities.first(where: { $0["recipient"] as? String == recipient })?["identity"] as? String
  else {
    throw SmokeFailure.fixture("Go zero-key recovery fixture is incomplete")
  }
  let root = FileManager.default.temporaryDirectory
    .appendingPathComponent("symvault-ios-zero-key-\(UUID().uuidString)", isDirectory: true)
  defer { try? FileManager.default.removeItem(at: root) }
  try FileManager.default.createDirectory(
    at: root.appendingPathComponent("entries", isDirectory: true),
    withIntermediateDirectories: true)
  let quotedBytes = try JSONSerialization.data(withJSONObject: root.path, options: .fragmentsAllowed)
  guard let quotedPath = String(data: quotedBytes, encoding: .utf8) else {
    throw SmokeFailure.fixture("Go zero-key vault path is not UTF-8")
  }
  try Data("vaultDir: \(quotedPath)\nvault:\n  format_version: 2\n".utf8)
    .write(to: root.appendingPathComponent("config.yaml"))
  try Data("\(recipient)\n".utf8).write(to: root.appendingPathComponent("recipients.txt"))
  try encrypted.write(to: root.appendingPathComponent("identity.age"))
  let passphrase = String(repeating: "x", count: passphraseLength)
  guard try callVault(root, passphrase: passphrase, initialize: false) == Data(identity.utf8) else {
    throw SmokeFailure.contract("Rust FFI did not recover the Go zero-key identity")
  }
  guard
    try Data(contentsOf: root.appendingPathComponent("identity.age.bak")) == encrypted,
    try Data(contentsOf: root.appendingPathComponent("identity.age")) != encrypted
  else {
    throw SmokeFailure.contract("Rust FFI did not back up and replace the zero-key identity")
  }
}

func runContracts() throws {
  let identity = try verifyCryptoFixture()
  try verifyStoreFixture(identity: identity)
  try verifyMobileVaultFixture()
  try verifyZeroKeyRecovery()
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
