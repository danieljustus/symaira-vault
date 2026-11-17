#if os(macOS)
  import SwiftUI
  import SymairaTheme
  import SymvaultKit

  /// Detail column of the Entries page: one decrypted entry on a card.
  struct EntryDetailView: View {
    let detail: VaultEntryDetail
    let onEdit: () -> Void
    let onDelete: () -> Void
    @Environment(VaultStore.self) private var store

    var body: some View {
      ScrollView {
        VStack(alignment: .leading, spacing: SymairaSpacing.small) {
          header
          if let totp = detail.totp {
            SymairaFormDivider()
            TOTPSection(totp: totp, loadedAt: store.detailLoadedAt) {
              await store.load(path: detail.path)
            }
          }
          SymairaFormDivider()
          Text("FIELDS").symairaText(.sectionLabel)
          ForEach(sortedFields, id: \.0) { field, value in
            SecretFieldRow(field: field, value: value)
          }
          SymairaFormDivider()
          HStack(spacing: SymairaSpacing.medium) {
            Button(action: onEdit) { Label("Edit…", symairaIcon: .edit) }
              .symairaButtonStyle(.secondary)
            Button(role: .destructive, action: onDelete) { Label("Delete…", symairaIcon: .delete) }
              .symairaButtonStyle(.secondary)
          }
          .padding(.top, SymairaSpacing.xSmall)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
      }
      .symairaCard()
      .contextMenu {
        Button("Edit Entry…", action: onEdit)
        Divider()
        Button("Delete Entry…", role: .destructive, action: onDelete)
      }
    }

    private var header: some View {
      VStack(alignment: .leading, spacing: SymairaSpacing.xSmall) {
        Text(verbatim: title)
          .symairaText(.heading)
          .accessibilityAddTraits(.isHeader)
        Text(verbatim: detail.path)
          .symairaText(.monoSmall)
          .foregroundStyle(SymairaTokens.ink3)
          .textSelection(.enabled)
        if !detail.modified.isEmpty {
          Text("Modified \(detail.modified)").symairaText(.caption)
        }
        if let primary = detail.primarySecret {
          Button {
            store.copy(primary.value, label: fieldLabel(primary.field))
          } label: {
            Label("Copy \(fieldLabel(primary.field))", symairaIcon: .copy)
          }
          .symairaButtonStyle(.secondary)
          .keyboardShortcut("c", modifiers: [.command, .shift])
          .help("Copy \(fieldLabel(primary.field)) (⇧⌘C)")
          .padding(.top, SymairaSpacing.small)
        }
      }
    }

    private var sortedFields: [(String, JSONValue)] {
      let order = ["username", "password", "secret", "token", "api_key", "url", "notes", "totp"]
      return detail.fields.sorted {
        let left = order.firstIndex(of: $0.key) ?? order.count
        let right = order.firstIndex(of: $1.key) ?? order.count
        return left == right ? $0.key < $1.key : left < right
      }
    }

    private var title: String {
      detail.path.split(separator: "/").last.map(String.init) ?? detail.path
    }
  }

  func fieldLabel(_ field: String) -> String {
    switch field {
    case "url": return "URL"
    case "api_key": return "API Key"
    case "totp": return "TOTP"
    case "database_url": return "Database URL"
    default: return field.replacingOccurrences(of: "_", with: " ").capitalized
    }
  }

  private struct SecretFieldRow: View {
    let field: String
    let value: JSONValue
    @Environment(VaultStore.self) private var store
    @State private var isRevealed = false

    var body: some View {
      HStack(alignment: .firstTextBaseline, spacing: SymairaSpacing.small) {
        Text(fieldLabel(field))
          .symairaText(.secondary)
          .frame(width: 96, alignment: .leading)
        Group {
          if sensitive && !isRevealed {
            // Masked values are not selectable, so nothing can be dragged out
            // of a row that looks hidden.
            Text(verbatim: String(repeating: "•", count: 12))
              .accessibilityLabel("Hidden value")
          } else {
            Text(verbatim: value.displayString)
              .textSelection(.enabled)
              .lineLimit(field == "notes" ? 6 : 3)
          }
        }
        .symairaText(.monoSmall)
        .foregroundStyle(SymairaTokens.ink)
        .frame(maxWidth: .infinity, alignment: .leading)
        if sensitive {
          SymairaIconButton(
            isRevealed ? "Hide \(fieldLabel(field))" : "Show \(fieldLabel(field))",
            icon: isRevealed ? .hidden : .visible, size: 16
          ) {
            isRevealed.toggle()
          }
        }
        SymairaIconButton("Copy \(fieldLabel(field))", icon: .copy, size: 16) {
          store.copy(value.displayString, label: fieldLabel(field))
        }
      }
      .padding(.vertical, SymairaSpacing.xSmall)
      .contextMenu {
        Button("Copy \(fieldLabel(field))") {
          store.copy(value.displayString, label: fieldLabel(field))
        }
        if sensitive {
          Button(isRevealed ? "Hide Value" : "Show Value") { isRevealed.toggle() }
        }
      }
    }

    private var sensitive: Bool { VaultFieldSecurity.isSensitive(field) }
  }

  private struct TOTPSection: View {
    let totp: VaultTOTP
    let loadedAt: Date
    let refresh: () async -> Void
    @Environment(VaultStore.self) private var store

    var body: some View {
      TimelineView(.periodic(from: .now, by: 1)) { context in
        let remaining = remaining(at: context.date)
        VStack(alignment: .leading, spacing: SymairaSpacing.small) {
          Text("ONE-TIME CODE").symairaText(.sectionLabel)
          HStack(alignment: .firstTextBaseline, spacing: SymairaSpacing.medium) {
            Text(verbatim: groupedCode)
              .font(SymairaTypography.readout)
              .foregroundStyle(SymairaTokens.ink)
              .monospacedDigit()
              .textSelection(.enabled)
            Text("\(remaining) s left")
              .symairaText(.caption)
              .monospacedDigit()
            Spacer()
            SymairaIconButton("Copy One-Time Code", icon: .copy, size: 16) {
              store.copy(totp.code, label: "One-time code")
            }
          }
          ProgressView(value: Double(remaining), total: Double(max(totp.period, 1)))
            .progressViewStyle(SymairaProgressStyle(height: 4))
            .accessibilityLabel("Time left for this code")
            .accessibilityValue("\(remaining) seconds")
        }
      }
      .task(id: totp.code) {
        try? await Task.sleep(for: .seconds(max(totp.remaining, 1)))
        guard !Task.isCancelled else { return }
        await refresh()
      }
    }

    private var groupedCode: String {
      guard totp.code.count == 6 else { return totp.code }
      return "\(totp.code.prefix(3)) \(totp.code.suffix(3))"
    }

    private func remaining(at date: Date) -> Int {
      let elapsed = Int(date.timeIntervalSince(loadedAt))
      return max(totp.remaining - elapsed, 0)
    }
  }
#endif
