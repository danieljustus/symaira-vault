#if os(macOS)
  import SwiftUI
  import SymairaTheme
  import SymvaultKit
  import UniformTypeIdentifiers

  /// Review-gated credential intake: drop files, preview suggestions, stage a
  /// quarantined batch, review and promote.
  public struct IntakeView: View {
    @Environment(IntakeStore.self) private var store
    @State private var showFileImporter = false
    @State private var isDropTargeted = false

    public init() {}

    public var body: some View {
      VStack(alignment: .leading, spacing: 14) {
        header
        switch store.phase {
        case .idle, .previewing:
          dropZone
        case .reviewing:
          if store.importID == nil {
            previewList
          } else {
            reviewEditor
          }
        case .promoting:
          ProgressView("Batch wird übernommen …")
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        case .done:
          doneView
        case .failed:
          failedView
        }
      }
      .padding(20)
      .frame(minWidth: 640, minHeight: 520)
      .fileImporter(
        isPresented: $showFileImporter,
        allowedContentTypes: [.data],
        allowsMultipleSelection: true
      ) { result in
        if case .success(let urls) = result {
          store.addFiles(urls)
          Task { await store.runPreview() }
        }
      }
    }

    private var header: some View {
      HStack {
        VStack(alignment: .leading, spacing: 3) {
          Text("Credential-Intake")
            .font(.title2.weight(.semibold))
            .foregroundStyle(SymairaTheme.textPrimary)
          Text("Dateien prüfen, Vorschläge ansehen, quarantäniert übernehmen.")
            .font(.callout)
            .foregroundStyle(SymairaTheme.textSecondary)
        }
        Spacer()
        if !store.files.isEmpty {
          Button("Zurücksetzen", role: .destructive) { store.clear() }
            .buttonStyle(.plain)
            .foregroundStyle(.secondary)
        }
      }
    }

    private var dropZone: some View {
      VStack(spacing: 14) {
        Image(systemName: "tray.and.arrow.down.fill")
          .font(.system(size: 40, weight: .light))
          .foregroundStyle(isDropTargeted ? SymairaTheme.goldPrimary : SymairaTheme.textSecondary)
        Text("Credential-Dateien hierher ziehen")
          .font(.headline)
          .foregroundStyle(SymairaTheme.textPrimary)
        Text(
          "Text, .env, JSON, Zertifikate/Schlüssel, Screenshots und Backup-Codes.\n"
            + "Es wird nichts geschrieben, bis du den Batch prüfst und übernimmst."
        )
        .font(.callout)
        .foregroundStyle(SymairaTheme.textSecondary)
        .multilineTextAlignment(.center)
        Button("Dateien auswählen …") { showFileImporter = true }
          .buttonStyle(SymairaPrimaryButtonStyle())

        if store.isBusy {
          ProgressView("Dateien werden geprüft …")
            .padding(.top, 6)
        }
      }
      .frame(maxWidth: .infinity, minHeight: 240)
      .padding(24)
      .background(
        RoundedRectangle(cornerRadius: 14)
          .stroke(
            isDropTargeted ? SymairaTheme.goldPrimary : SymairaTheme.borderGlass,
            style: StrokeStyle(lineWidth: isDropTargeted ? 2 : 1, dash: [6, 4]))
      )
      .contentShape(Rectangle())
      .onDrop(of: [.fileURL], isTargeted: $isDropTargeted) { providers in
        handleDrop(providers)
      }
    }

    private func handleDrop(_ providers: [NSItemProvider]) -> Bool {
      var urls: [URL] = []
      let group = DispatchGroup()
      for provider in providers {
        guard provider.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) else {
          continue
        }
        group.enter()
        provider.loadItem(forTypeIdentifier: UTType.fileURL.identifier, options: nil) { item, _ in
          if let data = item as? Data, let url = URL(dataRepresentation: data, relativeTo: nil) {
            urls.append(url)
          } else if let url = item as? URL {
            urls.append(url)
          }
          group.leave()
        }
      }
      group.notify(queue: .main) {
        guard !urls.isEmpty else { return }
        store.addFiles(urls)
        Task { await store.runPreview() }
      }
      return true
    }

    private var previewList: some View {
      ScrollView {
        VStack(alignment: .leading, spacing: 10) {
          ForEach(store.preview?.results ?? []) { result in
            resultRow(result)
          }
          HStack {
            Spacer()
            Toggle(
              "Quellen nach verifizierter Aufnahme in den Papierkorb",
              isOn: Binding(get: { store.moveToTrash }, set: { store.moveToTrash = $0 })
            )
            .toggleStyle(.checkbox)
            .foregroundStyle(SymairaTheme.textSecondary)
            Button("In Quarantäne aufnehmen") { Task { await store.stage() } }
              .buttonStyle(SymairaPrimaryButtonStyle())
              .disabled(store.isBusy || (store.preview?.results.contains { $0.isOK } ?? false) == false)
          }
          .padding(.top, 8)
        }
      }
    }

    private func resultRow(_ result: IntakeFileResult) -> some View {
      HStack(alignment: .top, spacing: 12) {
        Image(systemName: statusIcon(result.status))
          .foregroundStyle(statusColor(result.status))
          .frame(width: 18)
        VStack(alignment: .leading, spacing: 3) {
          Text(result.provenance?.sourceName ?? result.file)
            .font(.callout.weight(.medium))
            .foregroundStyle(SymairaTheme.textPrimary)
          if let reason = result.reason, !reason.isEmpty {
            Text(reason)
              .font(.caption)
              .foregroundStyle(SymairaTheme.warning)
          } else if let prov = result.provenance {
            Text("\(prov.sourceType) · \(ByteCountFormatter.string(fromByteCount: prov.size, countStyle: .file)) · sha256 \(prov.sha256.prefix(12))")
              .font(.caption)
              .foregroundStyle(SymairaTheme.textSecondary)
          }
          if !result.duplicates.isEmpty {
            Text("Duplikat: bereits in \(result.duplicates.joined(separator: ", "))")
              .font(.caption)
              .foregroundStyle(SymairaTheme.warning)
          }
          if !result.suggestions.isEmpty {
            Text(result.suggestions.map { $0.attachment ? "attachment: \($0.field)" : "\($0.field)" }.joined(separator: " · "))
              .font(.caption)
              .foregroundStyle(SymairaTheme.textSecondary)
          }
        }
        Spacer()
      }
      .padding(10)
      .glassmorphicPanel(cornerRadius: 10, addCorners: false)
    }

    private func statusIcon(_ status: String) -> String {
      switch status {
      case "ok": return "checkmark.circle.fill"
      case "skipped": return "minus.circle"
      default: return "exclamationmark.triangle.fill"
      }
    }

    private func statusColor(_ status: String) -> Color {
      switch status {
      case "ok": return .green
      case "skipped": return .orange
      default: return .red
      }
    }

    private var reviewEditor: some View {
      VStack(alignment: .leading, spacing: 12) {
        if let importID = store.importID {
          Label("Batch \(importID)", systemImage: "shippingbox.fill")
            .font(.callout.weight(.medium))
            .foregroundStyle(SymairaTheme.goldPrimary)
        }
        Text("Prüfe die Vorschläge. Die Werte bleiben verschlüsselt im Vault — nach dem Übernehmen kannst du Einträge wie gewohnt bearbeiten.")
          .font(.callout)
          .foregroundStyle(SymairaTheme.textSecondary)

        ScrollView {
          VStack(spacing: 10) {
            ForEach(Array(store.drafts.enumerated()), id: \.element.id) { index, _ in
              draftRow(
                Binding(
                  get: { store.drafts[index] },
                  set: { store.drafts[index] = $0 }
                )
              )
            }
          }
        }

        HStack {
          Spacer()
          Button("Verwerfen") { store.clear() }
            .buttonStyle(.plain)
            .foregroundStyle(.secondary)
          Button("Batch übernehmen") { Task { await store.promote() } }
            .buttonStyle(SymairaPrimaryButtonStyle())
            .disabled(store.isBusy || store.drafts.isEmpty)
        }
      }
    }

    private func draftRow(_ draft: Binding<IntakeReviewDraft>) -> some View {
      VStack(alignment: .leading, spacing: 8) {
        HStack {
          Image(systemName: "doc.text.fill")
            .foregroundStyle(SymairaTheme.goldPrimary)
          Text(draft.wrappedValue.sourceName)
            .font(.callout.weight(.medium))
            .foregroundStyle(SymairaTheme.textPrimary)
          Spacer()
          Text("\(draft.wrappedValue.sourceType) · \(draft.wrappedValue.size) bytes")
            .font(.caption)
            .foregroundStyle(SymairaTheme.textSecondary)
        }
        HStack(spacing: 8) {
          Text("Ziel")
            .font(.caption)
            .foregroundStyle(SymairaTheme.textSecondary)
          TextField("Zielpfad", text: draft.targetPath)
            .textFieldStyle(.plain)
            .font(.callout.monospaced())
            .padding(6)
            .background(SymairaTheme.bgCard)
            .cornerRadius(6)
        }
        ForEach(draft.wrappedValue.fields.keys.sorted(), id: \.self) { key in
          HStack(spacing: 8) {
            Text("Feld")
              .font(.caption)
              .foregroundStyle(SymairaTheme.textSecondary)
            TextField("Feldname", text: Binding(
              get: { draft.wrappedValue.fields[key] ?? key },
              set: { draft.wrappedValue.fields[key] = $0 }
            ))
            .textFieldStyle(.plain)
            .font(.callout.monospaced())
            .padding(6)
            .background(SymairaTheme.bgCard)
            .cornerRadius(6)
          }
        }
        Toggle("Originaldatei als verschlüsselten Anhang behalten", isOn: draft.keepAttachment)
          .toggleStyle(.checkbox)
          .font(.caption)
          .foregroundStyle(SymairaTheme.textSecondary)
        if !draft.wrappedValue.warnings.isEmpty {
          Text(draft.wrappedValue.warnings.joined(separator: "\n"))
            .font(.caption)
            .foregroundStyle(SymairaTheme.warning)
        }
      }
      .padding(12)
      .glassmorphicPanel(cornerRadius: 10, addCorners: false)
    }

    private var doneView: some View {
      VStack(spacing: 16) {
        Image(systemName: "checkmark.seal.fill")
          .font(.system(size: 44, weight: .light))
          .foregroundStyle(SymairaTheme.positive)
        Text(store.notice ?? "Batch übernommen.")
          .font(.headline)
          .foregroundStyle(SymairaTheme.textPrimary)
        Button("Weitere Dateien aufnehmen") { store.clear() }
          .buttonStyle(SymairaPrimaryButtonStyle())
      }
      .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var failedView: some View {
      VStack(spacing: 16) {
        Image(systemName: "exclamationmark.shield.fill")
          .font(.system(size: 40, weight: .light))
          .foregroundStyle(SymairaTheme.critical)
        Text(store.errorMessage ?? "Unbekannter Fehler")
          .foregroundStyle(SymairaTheme.textSecondary)
          .multilineTextAlignment(.center)
        Button("Erneut versuchen") { store.clear() }
          .buttonStyle(SymairaPrimaryButtonStyle())
      }
      .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
  }
#endif
