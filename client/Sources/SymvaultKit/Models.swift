import Foundation

public enum JSONValue: Codable, Equatable, Sendable {
  case string(String)
  case number(Double)
  case bool(Bool)
  case object([String: JSONValue])
  case array([JSONValue])
  case null

  public init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    if container.decodeNil() {
      self = .null
    } else if let value = try? container.decode(Bool.self) {
      self = .bool(value)
    } else if let value = try? container.decode(Double.self) {
      self = .number(value)
    } else if let value = try? container.decode(String.self) {
      self = .string(value)
    } else if let value = try? container.decode([String: JSONValue].self) {
      self = .object(value)
    } else if let value = try? container.decode([JSONValue].self) {
      self = .array(value)
    } else {
      throw DecodingError.dataCorruptedError(
        in: container,
        debugDescription: "Unsupported JSON value"
      )
    }
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.singleValueContainer()
    switch self {
    case .string(let value): try container.encode(value)
    case .number(let value): try container.encode(value)
    case .bool(let value): try container.encode(value)
    case .object(let value): try container.encode(value)
    case .array(let value): try container.encode(value)
    case .null: try container.encodeNil()
    }
  }

  public var displayString: String {
    switch self {
    case .string(let value): return value
    case .number(let value): return value.formatted()
    case .bool(let value): return value ? "true" : "false"
    case .object(let value):
      return value.keys.sorted().map { "\($0): \(value[$0]?.displayString ?? "")" }.joined(
        separator: "\n")
    case .array(let value): return value.map(\.displayString).joined(separator: ", ")
    case .null: return "—"
    }
  }
}

public struct VaultEntrySummary: Codable, Identifiable, Equatable, Sendable {
  public let path: String
  public let type: String?
  public let usageHint: String?
  public let autoRotate: Bool?
  public let hasValue: Bool?
  public let fieldCount: Int?

  public var id: String { path }

  public var title: String {
    path.split(separator: "/").last.map(String.init) ?? path
  }

  public var group: String {
    let parts = path.split(separator: "/")
    return parts.count > 1 ? String(parts[0]) : "Allgemein"
  }

  public init(
    path: String,
    type: String? = nil,
    usageHint: String? = nil,
    autoRotate: Bool? = nil,
    hasValue: Bool? = nil,
    fieldCount: Int? = nil
  ) {
    self.path = path
    self.type = type
    self.usageHint = usageHint
    self.autoRotate = autoRotate
    self.hasValue = hasValue
    self.fieldCount = fieldCount
  }
}

public struct VaultTOTP: Codable, Equatable, Sendable {
  public let code: String
  public let period: Int
  public let remaining: Int

  public init(code: String, period: Int, remaining: Int) {
    self.code = code
    self.period = period
    self.remaining = remaining
  }
}

public struct VaultEntryDetail: Codable, Equatable, Sendable {
  public let fields: [String: JSONValue]
  public let totp: VaultTOTP?
  public let path: String
  public let modified: String

  public init(fields: [String: JSONValue], totp: VaultTOTP?, path: String, modified: String) {
    self.fields = fields
    self.totp = totp
    self.path = path
    self.modified = modified
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: FlexibleCodingKey.self)
    fields = try container.decodeEither([String: JSONValue].self, lower: "fields", upper: "Fields")
    totp = try container.decodeIfPresentEither(VaultTOTP.self, lower: "totp", upper: "TOTP")
    path = try container.decodeEither(String.self, lower: "path", upper: "Path")
    modified = try container.decodeEither(String.self, lower: "modified", upper: "Modified")
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: FlexibleCodingKey.self)
    try container.encode(fields, forKey: FlexibleCodingKey("fields"))
    try container.encodeIfPresent(totp, forKey: FlexibleCodingKey("totp"))
    try container.encode(path, forKey: FlexibleCodingKey("path"))
    try container.encode(modified, forKey: FlexibleCodingKey("modified"))
  }

  public var primarySecret: (field: String, value: String)? {
    for key in ["password", "secret", "token", "api_key", "private_key", "database_url"] {
      if let value = fields[key]?.displayString, !value.isEmpty {
        return (key, value)
      }
    }
    return nil
  }
}

public struct VaultDraft: Equatable, Sendable {
  public var path = ""
  public var username = ""
  public var secret = ""
  public var url = ""
  public var notes = ""
  public var type = "password"
  public var usageHint = ""
  public var totpSecret = ""
  public var totpIssuer = ""
  public var totpAccount = ""

  public init() {}

  public init(detail: VaultEntryDetail, type: String? = nil, usageHint: String? = nil) {
    path = detail.path
    username = detail.fields["username"]?.displayString ?? ""
    secret = detail.primarySecret?.value ?? ""
    url = detail.fields["url"]?.displayString ?? ""
    notes = detail.fields["notes"]?.displayString ?? ""
    self.type = type ?? "password"
    self.usageHint = usageHint ?? ""
  }
}

public enum VaultFieldSecurity {
  public static func isSensitive(_ field: String) -> Bool {
    let key = field.lowercased()
    return [
      "password", "secret", "token", "api_key", "private_key", "totp", "certificate",
      "database_url",
    ]
    .contains { key.contains($0) }
  }
}

private struct FlexibleCodingKey: CodingKey {
  let stringValue: String
  let intValue: Int? = nil

  init(_ stringValue: String) {
    self.stringValue = stringValue
  }

  init?(stringValue: String) {
    self.init(stringValue)
  }

  init?(intValue: Int) {
    return nil
  }
}

extension KeyedDecodingContainer where Key == FlexibleCodingKey {
  fileprivate func decodeEither<T: Decodable>(_ type: T.Type, lower: String, upper: String) throws
    -> T
  {
    if let value = try decodeIfPresent(type, forKey: FlexibleCodingKey(lower)) {
      return value
    }
    return try decode(type, forKey: FlexibleCodingKey(upper))
  }

  fileprivate func decodeIfPresentEither<T: Decodable>(_ type: T.Type, lower: String, upper: String)
    throws -> T?
  {
    if contains(FlexibleCodingKey(lower)) {
      return try decodeIfPresent(type, forKey: FlexibleCodingKey(lower))
    }
    return try decodeIfPresent(type, forKey: FlexibleCodingKey(upper))
  }
}
