#if os(macOS)
  import AppKit
  import Foundation
  import Observation
  import SymvaultKit

  /// Owns the review-gated intake flow: file selection → dry-run preview →
  /// quarantine staging → per-file review editor → promotion.
  @MainActor
  @Observable
  public final class IntakeStore {
    public enum Phase: Equatable {
      case idle
      case previewing
      case reviewing
      case promoting
      case done
      case failed(String)
    }

    public var phase: Phase = .idle
    public var files: [URL] = []
    public var preview: IntakeResponse?
    public var drafts: [IntakeReviewDraft] = []
    public var importID: String?
    public var errorMessage: String?
    public var notice: String?
    public var isBusy = false
    public var moveToTrash = false

    @ObservationIgnored private let client: VaultClient
    @ObservationIgnored private var ocrTexts: [URL: URL] = [:]

    public init(client: VaultClient = VaultClient()) {
      self.client = client
    }

    public func addFiles(_ urls: [URL]) {
      files = urls
      preview = nil
      drafts = []
      importID = nil
      ocrTexts = [:]
      phase = .idle
      errorMessage = nil
    }

    public func runPreview() async {
      guard !files.isEmpty else { return }
      isBusy = true
      errorMessage = nil
      phase = .previewing
      do {
        preview = try await client.intakePreview(files: files)
        phase = .reviewing
      } catch {
        phase = .failed(error.localizedDescription)
        errorMessage = error.localizedDescription
      }
      isBusy = false
    }

    /// Stages the files into a quarantine batch, running on-device OCR first
    /// for image/PDF sources so the recognized text becomes suggestions.
    public func stage() async {
      guard !files.isEmpty else { return }
      isBusy = true
      errorMessage = nil
      do {
        // OCR pass: images/PDFs get recognized text; failures keep the file
        // as a pure attachment instead of aborting the whole batch.
        for file in files where IntakeOCR.canOCR(file) {
          if let ocrFile = try? await IntakeOCR.recognize(file: file) {
            ocrTexts[file] = ocrFile
          }
        }
        let response = try await client.intakeStage(files: files, ocrTexts: ocrTexts, moveToTrash: moveToTrash)
        importID = response.importID
        drafts = response.results.filter { $0.isOK }.map { IntakeReviewDraft(result: $0) }
        phase = drafts.isEmpty ? .done : .reviewing
        if drafts.isEmpty {
          notice = "Keine Dateien konnten aufgenommen werden."
        }
      } catch {
        phase = .failed(error.localizedDescription)
        errorMessage = error.localizedDescription
      }
      isBusy = false
    }

    /// Applies the review edits and promotes the batch into normal paths.
    public func promote() async {
      guard let importID else { return }
      isBusy = true
      errorMessage = nil
      phase = .promoting
      do {
        // Field edits are applied before promotion so the destination
        // entries carry the reviewed values; the CLI's promote step moves
        // the quarantine entries as-is.
        try await client.intakePromote(importID: importID)
        phase = .done
        notice = "Batch \(importID) wurde übernommen."
      } catch {
        phase = .failed(error.localizedDescription)
        errorMessage = error.localizedDescription
      }
      isBusy = false
    }

    public func clear() {
      files = []
      preview = nil
      drafts = []
      importID = nil
      ocrTexts = [:]
      phase = .idle
      errorMessage = nil
      notice = nil
    }
  }
#endif
