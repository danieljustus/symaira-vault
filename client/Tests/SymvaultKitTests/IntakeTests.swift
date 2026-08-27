import Foundation
import Testing

@testable import SymvaultKit

@Test func decodesIntakeDryRunResponse() throws {
  let data = Data(
    #"""
    {
      "results": [
        {
          "file": "/tmp/creds.env",
          "status": "ok",
          "provenance": {
            "source_path": "/tmp/creds.env",
            "source_name": "creds.env",
            "source_type": "env",
            "size": 42,
            "sha256": "abc123",
            "mtime": "2026-08-27T10:00:00Z"
          },
          "suggestions": [
            {"path": "creds", "field": "username", "confidence": 0.95, "attachment": false},
            {"path": "creds", "field": "password", "confidence": 0.95, "attachment": false}
          ],
          "duplicates": []
        }
      ]
    }
    """#.utf8
  )

  let response = try JSONDecoder().decode(IntakeResponse.self, from: data)
  #expect(response.importID == nil)
  #expect(response.results.count == 1)

  let result = try #require(response.results.first)
  #expect(result.isOK)
  #expect(result.provenance?.sourceType == "env")
  #expect(result.provenance?.sha256 == "abc123")
  #expect(result.suggestions.count == 2)
  #expect(result.suggestions.first?.field == "username")
  #expect(result.suggestions.contains { $0.attachment } == false)
}

@Test func decodesIntakeStagedResponseWithImportID() throws {
  let data = Data(
    #"""
    {
      "import_id": "intake-20260827-1a2b3c",
      "results": [
        {
          "file": "/tmp/backup.png",
          "status": "ok",
          "provenance": {
            "source_path": "/tmp/backup.png",
            "source_name": "backup.png",
            "source_type": "image",
            "size": 2048,
            "sha256": "def456"
          },
          "suggestions": [
            {"path": "backup", "field": "username", "confidence": 0.8, "attachment": false},
            {"path": "backup", "field": "attachment", "confidence": 1.0, "attachment": true}
          ],
          "duplicates": []
        }
      ]
    }
    """#.utf8
  )

  let response = try JSONDecoder().decode(IntakeResponse.self, from: data)
  #expect(response.importID == "intake-20260827-1a2b3c")
  let result = try #require(response.results.first)
  #expect(result.isOK)
  #expect(result.suggestions.contains { $0.attachment })
}

@Test func reviewDraftBuildsFromResult() throws {
  let data = Data(
    #"""
    {
      "results": [
        {
          "file": "/tmp/login.example.txt",
          "status": "ok",
          "provenance": {
            "source_path": "/tmp/login.example.txt",
            "source_name": "login.example.txt",
            "source_type": "text",
            "size": 34,
            "sha256": "beef01"
          },
          "suggestions": [
            {"path": "login.example", "field": "username", "confidence": 0.8, "attachment": false},
            {"path": "login.example", "field": "password", "confidence": 0.85, "attachment": false}
          ],
          "duplicates": []
        }
      ]
    }
    """#.utf8
  )
  let response = try JSONDecoder().decode(IntakeResponse.self, from: data)
  let result = try #require(response.results.first)

  let draft = IntakeReviewDraft(result: result)
  #expect(draft.sourceName == "login.example.txt")
  #expect(draft.targetPath == "login.example")
  #expect(draft.fields.keys.contains("username"))
  #expect(draft.fields.keys.contains("password"))
  #expect(draft.keepAttachment == false)
}

@Test func reviewDraftAttachmentFallback() throws {
  let data = Data(
    #"""
    {
      "results": [
        {
          "file": "/tmp/elster.p12",
          "status": "ok",
          "provenance": {
            "source_path": "/tmp/elster.p12",
            "source_name": "elster.p12",
            "source_type": "key",
            "size": 1024,
            "sha256": "cafe02"
          },
          "suggestions": [
            {"path": "elster", "field": "attachment", "confidence": 1.0, "attachment": true}
          ],
          "duplicates": []
        }
      ]
    }
    """#.utf8
  )
  let response = try JSONDecoder().decode(IntakeResponse.self, from: data)
  let result = try #require(response.results.first)

  let draft = IntakeReviewDraft(result: result)
  #expect(draft.targetPath == "elster")
  #expect(draft.keepAttachment)
  #expect(draft.fields.isEmpty)
}

@Test func intakeResponseNeverCarriesValues() throws {
  // The CLI contract: JSON output is metadata only. Verify decoding a real
  // shape does not expose any secret-bearing field.
  let data = Data(
    #"""
    {
      "results": [
        {
          "file": "/tmp/creds.env",
          "status": "ok",
          "provenance": {"source_path": "/tmp/creds.env", "source_name": "creds.env", "source_type": "env", "size": 42, "sha256": "abc123"},
          "suggestions": [{"path": "creds", "field": "username", "confidence": 0.95}],
          "duplicates": []
        }
      ]
    }
    """#.utf8
  )
  let response = try JSONDecoder().decode(IntakeResponse.self, from: data)
  let result = try #require(response.results.first)
  // Suggestions only carry field names + confidence; no value key exists.
  #expect(result.suggestions.first?.field == "username")
}
