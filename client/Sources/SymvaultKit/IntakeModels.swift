#if os(macOS)
  import Foundation

  /// Decodable mirror of `symvault intake --json` output. Metadata only —
  /// the CLI never emits extracted secret values.
  public struct IntakeResponse: Decodable, Sendable {
    public let importID: String?
    public let results: [IntakeFileResult]

    public init(importID: String?, results: [IntakeFileResult]) {
      self.importID = importID
      self.results = results
    }

    enum CodingKeys: String, CodingKey {
      case importID = "import_id"
      case results
    }
  }

  public struct IntakeFileResult: Decodable, Sendable, Identifiable {
    public let file: String
    public let status: String
    public let reason: String?
    public let provenance: IntakeProvenance?
    public let suggestions: [IntakeSuggestion]
    public let duplicates: [String]

    public var id: String { file }

    public var isOK: Bool { status == "ok" }
    public var isSkipped: Bool { status == "skipped" }

    public init(
      file: String, status: String, reason: String?, provenance: IntakeProvenance?,
      suggestions: [IntakeSuggestion], duplicates: [String]
    ) {
      self.file = file
      self.status = status
      self.reason = reason
      self.provenance = provenance
      self.suggestions = suggestions
      self.duplicates = duplicates
    }
  }

  public struct IntakeProvenance: Decodable, Sendable {
    public let sourcePath: String
    public let sourceName: String
    public let sourceType: String
    public let size: Int64
    public let sha256: String

    public init(sourcePath: String, sourceName: String, sourceType: String, size: Int64, sha256: String) {
      self.sourcePath = sourcePath
      self.sourceName = sourceName
      self.sourceType = sourceType
      self.size = size
      self.sha256 = sha256
    }

    enum CodingKeys: String, CodingKey {
      case sourcePath = "source_path"
      case sourceName = "source_name"
      case sourceType = "source_type"
      case size
      case sha256
    }
  }

  public struct IntakeSuggestion: Decodable, Sendable, Identifiable {
    public let path: String
    public let field: String
    public let confidence: Double
    public let warning: String?
    public let attachment: Bool

    public var id: String { "\(path)/\(field)" }

    public init(path: String, field: String, confidence: Double, warning: String?, attachment: Bool) {
      self.path = path
      self.field = field
      self.confidence = confidence
      self.warning = warning
      self.attachment = attachment
    }

    enum CodingKeys: String, CodingKey {
      case path, field, confidence, warning, attachment
    }

    public init(from decoder: Decoder) throws {
      let c = try decoder.container(keyedBy: CodingKeys.self)
      path = try c.decode(String.self, forKey: .path)
      field = try c.decode(String.self, forKey: .field)
      confidence = try c.decodeIfPresent(Double.self, forKey: .confidence) ?? 0
      warning = try c.decodeIfPresent(String.self, forKey: .warning)
      // The CLI serializes attachment with omitempty, so a missing key means false.
      attachment = try c.decodeIfPresent(Bool.self, forKey: .attachment) ?? false
    }
  }

  /// A user-editable review row for one intake file.
  public struct IntakeReviewDraft: Identifiable, Sendable {
    public let file: String
    public let sourceName: String
    public let sourceType: String
    public let sha256: String
    public let size: Int64
    public var targetPath: String
    public var fields: [String: String]
    public var keepAttachment: Bool
    public let warnings: [String]

    public var id: String { file }

    public init(result: IntakeFileResult) {
      self.file = result.file
      self.sourceName = result.provenance?.sourceName ?? URL(fileURLWithPath: result.file).lastPathComponent
      self.sourceType = result.provenance?.sourceType ?? "unknown"
      self.sha256 = result.provenance?.sha256 ?? ""
      self.size = result.provenance?.size ?? 0
      self.targetPath = result.suggestions.first(where: { !$0.attachment })?.path
        ?? result.suggestions.first?.path
        ?? IntakeReviewDraft.stem(from: self.sourceName)
      var fields: [String: String] = [:]
      var warnings: [String] = []
      for s in result.suggestions where !s.attachment {
        if fields[s.field] == nil { fields[s.field] = "" }
        if let w = s.warning, !w.isEmpty { warnings.append(w) }
      }
      self.fields = fields
      self.keepAttachment = result.suggestions.contains(where: { $0.attachment })
      self.warnings = warnings
    }

    public static func stem(from name: String) -> String {
      let base = (name as NSString).deletingPathExtension
      return base.isEmpty ? "entry" : base
    }
  }
#endif
