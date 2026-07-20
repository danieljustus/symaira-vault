import Foundation
import Testing

@testable import SymvaultKit

@Test func decodesCurrentGoEntryShape() throws {
  let data = Data(
    #"{"Fields":{"username":"daniel","password":"correct horse"},"TOTP":{"code":"123456","period":30,"remaining":18},"Path":"work/github","Modified":"2026-07-20 11:45"}"#
      .utf8
  )
  let detail = try JSONDecoder().decode(VaultEntryDetail.self, from: data)

  #expect(detail.path == "work/github")
  #expect(detail.primarySecret?.field == "password")
  #expect(detail.primarySecret?.value == "correct horse")
  #expect(detail.totp?.code == "123456")
}

@Test func decodesCanonicalLowercaseEntryShape() throws {
  let data = Data(
    #"{"fields":{"api_key":"sk-local"},"totp":null,"path":"agents/local","modified":"2026-07-20 11:45"}"#
      .utf8
  )
  let detail = try JSONDecoder().decode(VaultEntryDetail.self, from: data)

  #expect(detail.path == "agents/local")
  #expect(detail.primarySecret?.field == "api_key")
  #expect(detail.primarySecret?.value == "sk-local")
}

@Test func groupsEntriesByFirstPathComponent() {
  #expect(VaultEntrySummary(path: "work/github").group == "work")
  #expect(VaultEntrySummary(path: "github").group == "Allgemein")
  #expect(VaultEntrySummary(path: "work/github").title == "github")
}

@Test func classifiesSensitiveFields() {
  #expect(VaultFieldSecurity.isSensitive("password"))
  #expect(VaultFieldSecurity.isSensitive("github_api_key"))
  #expect(!VaultFieldSecurity.isSensitive("username"))
}
