#if os(macOS)
  import Foundation
  import Vision

  /// On-device OCR for intake screenshots and scans. Text recognition runs
  /// locally via the Vision framework — no cloud OCR, no telemetry. The
  /// recognized lines are written to a private text file that the CLI's
  /// `--ocr-text` path turns into structured suggestions.
  public enum IntakeOCR {
    public enum OCRSource: Sendable {
      case image
      case pdf
    }

    /// Recognizes text in an image or PDF page range and writes the lines to
    /// a temp text file. Returns the file URL plus the recognized source kind.
    public static func recognize(
      file: URL, outputDirectory: URL? = nil
    ) async throws -> URL {
      let directory = outputDirectory ?? FileManager.default.temporaryDirectory
      try FileManager.default.createDirectory(
        at: directory, withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700])
      let out = directory.appendingPathComponent("ocr-\(UUID().uuidString).txt")

      let handler = VNImageRequestHandler(url: file, options: [:])
      let request = VNRecognizeTextRequest()
      request.recognitionLevel = .accurate
      request.usesLanguageCorrection = true
      request.recognitionLanguages = ["de-DE", "en-US"]

      try handler.perform([request])

      var lines: [String] = []
      for observation in request.results ?? [] {
        guard let candidate = observation.topCandidates(1).first else { continue }
        let text = candidate.string.trimmingCharacters(in: .whitespacesAndNewlines)
        if !text.isEmpty { lines.append(text) }
      }

      let content = lines.joined(separator: "\n") + (lines.isEmpty ? "" : "\n")
      try content.write(to: out, atomically: true, encoding: .utf8)
      return out
    }

    /// Reports whether the file looks like an OCR-able image or PDF.
    public static func canOCR(_ file: URL) -> Bool {
      switch file.pathExtension.lowercased() {
      case "png", "jpg", "jpeg", "gif", "webp", "heic", "pdf":
        return true
      default:
        return false
      }
    }
  }
#endif
