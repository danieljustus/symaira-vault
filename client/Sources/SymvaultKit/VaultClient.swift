#if os(macOS)
  import Foundation
  import SymairaCLIRunner
  import SymairaToolKit

  public enum VaultClientError: Error, LocalizedError, Sendable {
    case binaryNotFound
    case invalidGeneratedPassword

    public var errorDescription: String? {
      switch self {
      case .binaryNotFound:
        return "symvault wurde weder in der App noch auf diesem Mac gefunden."
      case .invalidGeneratedPassword:
        return "symvault hat kein gültiges Passwort erzeugt."
      }
    }
  }

  public struct VaultRuntimeInfo: Equatable, Sendable {
    public let path: String
    public let source: String
    public let version: String?
    public let schemaVersion: Int?

    public init(path: String, source: String, version: String?, schemaVersion: Int?) {
      self.path = path
      self.source = source
      self.version = version
      self.schemaVersion = schemaVersion
    }
  }

  public struct VaultClient: Sendable {
    public static let expectedSchemaVersion = 1

    private let runner: CLIRunner
    private let locator: BinaryLocator
    private let tool: SymairaTool

    public init(userOverride: URL? = nil, timeout: Double = 30) {
      runner = CLIRunner(defaultTimeout: timeout)
      locator = BinaryLocator(userOverride: userOverride)
      tool =
        SymairaToolRegistry.tool(id: "symvault")
        ?? SymairaTool(
          id: "symvault",
          displayName: "Symaira Vault",
          binaryName: "symvault",
          homebrewFormula: "danieljustus/tap/symvault",
          mcpArgs: ["serve", "--stdio"]
        )
    }

    public func detect() async -> VaultRuntimeInfo? {
      guard let detected = await ToolDetector(locator: locator, runner: runner).detect(tool) else {
        return nil
      }
      return VaultRuntimeInfo(
        path: detected.location.url.path,
        source: detected.location.source.rawValue,
        version: detected.versionInfo?.version,
        schemaVersion: detected.versionInfo?.schemaVersion
      )
    }

    public func listEntries(profile: String? = nil) async throws -> [VaultEntrySummary] {
      try await runner.runDecoding(
        [VaultEntrySummary].self,
        executable: try executable(),
        arguments: arguments(profile: profile, command: ["list", "--output", "json"])
      )
    }

    public func entry(path: String, profile: String? = nil) async throws -> VaultEntryDetail {
      try await runner.runDecoding(
        VaultEntryDetail.self,
        executable: try executable(),
        arguments: arguments(profile: profile, command: ["get", path, "--output", "json"])
      )
    }

    public func isUnlocked(profile: String? = nil) async throws -> Bool {
      let result = try await runner.run(
        try executable(),
        arguments: arguments(profile: profile, command: ["unlock", "--check"]),
        timeout: 8
      )
      return result.exitCode == 0
    }

    public func unlock(passphrase: String, ttl: String = "15m", profile: String? = nil) async throws
    {
      let input = Data((passphrase + "\n").utf8)
      _ = try await runner.runChecked(
        try executable(),
        arguments: arguments(
          profile: profile, command: ["unlock", "--ttl", ttl, "--no-pipe-warning"]),
        stdin: input,
        timeout: 35
      )
    }

    public func lock(profile: String? = nil) async throws {
      _ = try await runner.runChecked(
        try executable(),
        arguments: arguments(profile: profile, command: ["lock"]),
        timeout: 8
      )
    }

    public func create(_ draft: VaultDraft, profile: String? = nil) async throws {
      var command = ["add", draft.path, "--stdin-value", "--type", draft.type]
      append("--username", value: draft.username, to: &command)
      append("--url", value: draft.url, to: &command)
      append("--notes", value: draft.notes, to: &command)
      append("--usage-hint", value: draft.usageHint, to: &command)

      var input = draft.secret + "\n"
      if !draft.totpSecret.isEmpty {
        command.append("--stdin-totp-secret")
        append("--totp-issuer", value: draft.totpIssuer, to: &command)
        append("--totp-account", value: draft.totpAccount, to: &command)
        input += draft.totpSecret + "\n"
      }

      _ = try await runner.runChecked(
        try executable(),
        arguments: arguments(profile: profile, command: command),
        stdin: Data(input.utf8)
      )
    }

    public func update(
      path: String,
      original: VaultEntryDetail,
      draft: VaultDraft,
      profile: String? = nil
    ) async throws {
      let secretField = original.primarySecret?.field ?? "password"
      let updates: [(String, String, String)] = [
        (secretField, original.primarySecret?.value ?? "", draft.secret),
        ("username", original.fields["username"]?.displayString ?? "", draft.username),
        ("url", original.fields["url"]?.displayString ?? "", draft.url),
        ("notes", original.fields["notes"]?.displayString ?? "", draft.notes),
      ]

      for (field, oldValue, newValue) in updates where !newValue.isEmpty && newValue != oldValue {
        _ = try await runner.runChecked(
          try executable(),
          arguments: arguments(
            profile: profile, command: ["set", "\(path).\(field)", "--stdin-value"]),
          stdin: Data((newValue + "\n").utf8)
        )
      }
    }

    public func delete(path: String, profile: String? = nil) async throws {
      _ = try await runner.runChecked(
        try executable(),
        arguments: arguments(
          profile: profile, command: ["delete", path, "--yes", "--output", "json"])
      )
    }

    public func generatePassword(length: Int, symbols: Bool, profile: String? = nil) async throws
      -> String
    {
      var command = ["generate", "--length", String(length)]
      if symbols { command.append("--symbols") }
      let data = try await runner.runChecked(
        try executable(),
        arguments: arguments(profile: profile, command: command),
        timeout: 8
      )
      guard
        let password = String(data: data, encoding: .utf8)?.trimmingCharacters(
          in: .whitespacesAndNewlines),
        !password.isEmpty
      else {
        throw VaultClientError.invalidGeneratedPassword
      }
      return password
    }

    private func executable() throws -> URL {
      guard let located = locator.locate(tool.binaryName) else {
        throw VaultClientError.binaryNotFound
      }
      return located.url
    }

    private func arguments(profile: String?, command: [String]) -> [String] {
      var result = ["--color", "never"]
      if let profile = profile?.trimmingCharacters(in: .whitespacesAndNewlines), !profile.isEmpty {
        result += ["--profile", profile]
      }
      result += command
      return result
    }

    private func append(_ flag: String, value: String, to arguments: inout [String]) {
      guard !value.isEmpty else { return }
      arguments += [flag, value]
    }
  }
#endif
