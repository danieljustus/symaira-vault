#if os(macOS)
  import Foundation
  import SymairaCLIRunner

  extension VaultClient {
    /// Validates and parses files without writing anything (dry-run).
    public func intakePreview(files: [URL], profile: String? = nil) async throws -> IntakeResponse {
      try await runner.runDecoding(
        IntakeResponse.self,
        executable: try executable(),
        arguments: arguments(
          profile: profile,
          command: ["intake"] + files.map(\.path) + ["--dry-run", "--json"])
      )
    }

    /// Stages files into a quarantined review batch and returns the import id.
    /// `ocrTexts` maps a source file URL to a text file with on-device OCR
    /// results whose lines become suggestions for image/PDF sources.
    public func intakeStage(
      files: [URL], ocrTexts: [URL: URL] = [:], moveToTrash: Bool = false, profile: String? = nil
    ) async throws -> IntakeResponse {
      var command = ["intake"] + files.map(\.path) + ["--json"]
      if moveToTrash { command.append("--move-to-trash") }
      for (source, ocr) in ocrTexts {
        command += ["--ocr-text", ocr.path, source.path]
      }
      let data = try await runner.runChecked(
        try executable(),
        arguments: arguments(profile: profile, command: command),
        timeout: 120
      )
      return try JSONDecoder().decode(IntakeResponse.self, from: data)
    }

    /// Lists quarantined import batches (import review list).
    public func intakeReviewBatches(profile: String? = nil) async throws -> [String] {
      let data = try await runner.runChecked(
        try executable(),
        arguments: arguments(profile: profile, command: ["import", "review", "list"]),
        timeout: 15
      )
      let text = String(data: data, encoding: .utf8) ?? ""
      return text.split(separator: "\n").map { String($0.split(separator: " ").first ?? "") }.filter { !$0.isEmpty }
    }

    /// Promotes a reviewed quarantine batch into normal vault paths.
    public func intakePromote(importID: String, overwrite: Bool = false, profile: String? = nil) async throws {
      var command = ["import", "review", "promote", importID]
      if overwrite { command.append("--overwrite") }
      _ = try await runner.runChecked(
        try executable(),
        arguments: arguments(profile: profile, command: command),
        timeout: 60
      )
    }
  }
#endif
