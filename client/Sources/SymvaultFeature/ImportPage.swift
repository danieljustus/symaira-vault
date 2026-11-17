#if os(macOS)
  import SwiftUI
  import SymairaTheme
  import SymvaultKit
  import UniformTypeIdentifiers

  /// Screen card. Destination: Import (3 of 3). Job: turn credential files
  /// into vault entries through a review gate; one primary action per phase
  /// (Choose Files…, Stage for Review, Add Batch to Vault, Import More Files).
  /// Data: `symvault intake` dry run, stage and promote over the CLI, plus
  /// on-device OCR for images and PDFs; nothing is written before staging.
  /// States: idle drop zone, checking files, preview, review, adding, done,
  /// failed with Start Over. Density: prose column. Platform: macOS workspace;
  /// files also arrive from Finder (Open With) and ⇧⌘I. No preference keys.
  struct ImportPage: View {
    let model: VaultAppModel
    @State private var showFileImporter = false
    @State private var isDropTargeted = false

    private var intake: IntakeStore { model.intake }

    var body: some View {
      SymairaPage(
        title: L("Import"), subtitle: L("Review credential files before they enter the vault")
      ) {
        Spacer()
        if !intake.files.isEmpty {
          Button(action: intake.clear) { Label(L("Start Over"), symairaIcon: .restart) }
            .symairaButtonStyle(.secondary)
            .disabled(intake.isBusy)
        }
      } content: {
        content
      }
      .fileImporter(
        isPresented: $showFileImporter, allowedContentTypes: [.data], allowsMultipleSelection: true
      ) { result in
        if case .success(let urls) = result {
          model.openImport(files: urls)
        }
      }
    }

    @ViewBuilder
    private var content: some View {
      switch intake.phase {
      case .idle:
        dropZone
      case .previewing:
        SymairaPageState(
          state: SymairaPageLoadState<Void>.loading, loading: L("Checking files…"),
          retry: rerunPreview
        ) { _ in EmptyView() }
      case .reviewing:
        if intake.importID == nil { previewList } else { reviewEditor }
      case .promoting:
        SymairaPageState(
          state: SymairaPageLoadState<Void>.loading, loading: L("Adding the batch to the vault…"),
          retry: {}
        ) { _ in EmptyView() }
      case .done:
        SymairaPageEmpty(
          icon: .success, title: L("Import Finished"),
          message: intake.notice ?? L("The batch was added to the vault.")
        ) {
          Button(L("Import More Files")) { intake.clear() }
            .symairaButtonStyle(.primary)
        }
      case .failed(let message):
        SymairaNotice(title: L("Import Failed"), message: message, tone: .critical)
        Button(L("Start Over")) { intake.clear() }
          .symairaButtonStyle(.secondary)
      }
    }

    private func rerunPreview() {
      Task { await intake.runPreview() }
    }

    // MARK: - Idle

    private var dropZone: some View {
      SymairaEmptyState(
        icon: .inbox,
        title: L("Drop Credential Files Here"),
        message:
          L(
            "Text, .env, JSON, certificates and keys, screenshots and backup codes. Nothing is written until you review and add the batch."
          )
      ) {
        Button(L("Choose Files…")) { showFileImporter = true }
          .symairaButtonStyle(.primary)
      }
      .frame(maxWidth: .infinity, minHeight: SymairaPageLayout.stateHeight)
      .symairaCard()
      .overlay {
        RoundedRectangle(cornerRadius: SymairaRadius.card, style: .continuous)
          .strokeBorder(SymairaTokens.focus, lineWidth: 2)
          .opacity(isDropTargeted ? 1 : 0)
      }
      .onDrop(of: [.fileURL], isTargeted: $isDropTargeted, perform: handleDrop)
      .accessibilityHint(L("Drop files, or choose them with the button."))
    }

    private func handleDrop(_ providers: [NSItemProvider]) -> Bool {
      let fileProviders = providers.filter {
        $0.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier)
      }
      guard !fileProviders.isEmpty else { return false }
      Task {
        var urls: [URL] = []
        for provider in fileProviders {
          if let url = await Self.loadURL(provider) { urls.append(url) }
        }
        model.openImport(files: urls)
      }
      return true
    }

    private static func loadURL(_ provider: NSItemProvider) async -> URL? {
      await withCheckedContinuation { continuation in
        _ = provider.loadObject(ofClass: URL.self) { url, _ in
          continuation.resume(returning: url)
        }
      }
    }

    // MARK: - Preview

    private var previewList: some View {
      VStack(alignment: .leading, spacing: SymairaSpacing.medium) {
        VStack(alignment: .leading, spacing: SymairaSpacing.small) {
          Text(L("FILES")).symairaText(.sectionLabel)
          ForEach(Array((intake.preview?.results ?? []).enumerated()), id: \.element.id) {
            index, result in
            if index > 0 { SymairaFormDivider() }
            resultRow(result)
          }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .symairaCard()

        SymairaFormSection(L("After Import")) {
          SymairaFormRow(
            L("Move Sources to Trash"),
            description: L("Only after the batch was verified in the vault.")
          ) {
            Toggle(isOn: Binding(get: { intake.moveToTrash }, set: { intake.moveToTrash = $0 })) {
              EmptyView()
            }
            .toggleStyle(.symairaSwitch)
            .centeredOnFormLabel()
            .accessibilityLabel(L("Move sources to Trash after import"))
          }
        }

        HStack(spacing: SymairaSpacing.medium) {
          Button(intake.isBusy ? L("Staging…") : L("Stage for Review")) {
            Task { await intake.stage() }
          }
          .symairaButtonStyle(.primary)
          .disabled(intake.isBusy || !hasImportableFile)
          if !hasImportableFile {
            Text(L("None of these files can be imported.")).symairaText(.caption)
          }
        }
      }
    }

    private var hasImportableFile: Bool {
      intake.preview?.results.contains { $0.isOK } ?? false
    }

    private func resultRow(_ result: IntakeFileResult) -> some View {
      HStack(alignment: .firstTextBaseline, spacing: SymairaSpacing.medium) {
        VStack(alignment: .leading, spacing: SymairaSpacing.xSmall) {
          Text(verbatim: result.provenance?.sourceName ?? result.file).symairaText(.bodyEmphasized)
          if let reason = result.reason, !reason.isEmpty {
            Text(verbatim: reason).symairaText(.caption)
          } else if let prov = result.provenance {
            Text(
              verbatim:
                "\(prov.sourceType) · \(ByteCountFormatter.string(fromByteCount: prov.size, countStyle: .file)) · sha256 \(prov.sha256.prefix(12))"
            )
            .symairaText(.caption)
          }
          if !result.duplicates.isEmpty {
            Text(L("Already in the vault as %@", result.duplicates.joined(separator: ", ")))
              .symairaText(.caption)
          }
          if !result.suggestions.isEmpty {
            Text(
              verbatim: result.suggestions.map {
                $0.attachment ? L("attachment: %@", $0.field) : $0.field
              }
              .joined(separator: " · ")
            )
            .symairaText(.monoSmall)
            .foregroundStyle(SymairaTokens.ink2)
          }
        }
        Spacer(minLength: 0)
        status(for: result)
      }
      .padding(.vertical, SymairaSpacing.xSmall)
    }

    private func status(for result: IntakeFileResult) -> some View {
      switch result.status {
      case "ok": SymairaStatusLabel(L("Ready"), tone: .positive)
      case "skipped": SymairaStatusLabel(L("Skipped"), tone: .warning)
      default: SymairaStatusLabel(L("Rejected"), tone: .critical)
      }
    }

    // MARK: - Review

    private var reviewEditor: some View {
      VStack(alignment: .leading, spacing: SymairaSpacing.medium) {
        SymairaNotice(
          title: intake.importID.map { L("Batch %@", $0) },
          message:
            L(
              "The files are staged in quarantine, encrypted. Check where each one goes, then add the batch. Rename or edit the entries afterwards on Entries."
            ),
          tone: .informative
        )
        ForEach(intake.drafts) { draft in
          draftCard(draft)
        }
        HStack(spacing: SymairaSpacing.medium) {
          Button(L("Discard Batch")) { intake.clear() }
            .symairaButtonStyle(.secondary)
          Button(L("Add Batch to Vault")) {
            Task {
              await intake.promote()
              model.refresh()
            }
          }
          .symairaButtonStyle(.primary)
          .disabled(intake.isBusy || intake.drafts.isEmpty)
        }
      }
    }

    /// Read-only: `import review promote` moves the staged entries as they are,
    /// so this card shows what will be written instead of offering edits that
    /// would be ignored.
    private func draftCard(_ draft: IntakeReviewDraft) -> some View {
      SymairaFormSection(draft.sourceName) {
        SymairaFormRow(
          L("Target Path"),
          description:
            "\(draft.sourceType) · \(ByteCountFormatter.string(fromByteCount: draft.size, countStyle: .file))"
        ) {
          Text(verbatim: draft.targetPath)
            .symairaText(.monoSmall)
            .foregroundStyle(SymairaTokens.ink)
            .textSelection(.enabled)
        }
        SymairaFormDivider()
        SymairaFormRow(L("Fields")) {
          Text(
            verbatim: draft.fields.isEmpty
              ? L("None") : draft.fields.keys.sorted().joined(separator: ", ")
          )
          .symairaText(.monoSmall)
          .foregroundStyle(SymairaTokens.ink)
        }
        SymairaFormDivider()
        SymairaFormRow(L("Original File")) {
          SymairaStatusLabel(
            draft.keepAttachment ? L("Kept as Encrypted Attachment") : L("Not Kept"),
            tone: draft.keepAttachment ? .positive : .neutral)
        }
        if !draft.warnings.isEmpty {
          SymairaNotice(message: draft.warnings.joined(separator: "\n"), tone: .warning)
            .padding(.bottom, SymairaSpacing.small)
        }
      }
    }
  }
#endif
