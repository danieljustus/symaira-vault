#if os(macOS)
  import SwiftUI
  import SymairaTheme
  import SymvaultKit

  struct EntryDetailView: View {
    let detail: VaultEntryDetail
    let onEdit: () -> Void
    let onDelete: () -> Void
    @Environment(VaultStore.self) private var store

    var body: some View {
      ScrollView {
        VStack(alignment: .leading, spacing: 22) {
          header

          if let totp = detail.totp {
            TOTPCard(totp: totp, loadedAt: store.detailLoadedAt) {
              await store.load(path: detail.path)
            }
          }

          VStack(alignment: .leading, spacing: 0) {
            ForEach(sortedFields, id: \.0) { field, value in
              SecretFieldRow(field: field, value: value)
              if field != sortedFields.last?.0 {
                Divider().overlay(Color.white.opacity(0.05))
              }
            }
          }
          .glassmorphicPanel(addCorners: false)

          metadataCard
        }
        .padding(28)
        .frame(maxWidth: 780, alignment: .leading)
        .frame(maxWidth: .infinity, alignment: .center)
      }
    }

    private var header: some View {
      HStack(alignment: .top, spacing: 18) {
        ZStack {
          RoundedRectangle(cornerRadius: 14)
            .fill(SymairaTheme.goldPrimary.opacity(0.09))
            .frame(width: 64, height: 64)
          Image(systemName: "lock.shield.fill")
            .font(.system(size: 27, weight: .light))
            .foregroundStyle(SymairaTheme.goldPrimary)
        }

        VStack(alignment: .leading, spacing: 5) {
          Text(title)
            .font(.largeTitle.weight(.semibold))
            .foregroundStyle(SymairaTheme.textPrimary)
          Text(detail.path)
            .font(.callout.monospaced())
            .foregroundStyle(SymairaTheme.textMuted)
            .textSelection(.enabled)
        }

        Spacer()

        if let primary = detail.primarySecret {
          Button {
            store.copy(primary.value, label: label(for: primary.field))
          } label: {
            Label("Kopieren", systemImage: "doc.on.doc.fill")
          }
          .buttonStyle(SymairaPrimaryButtonStyle())
        }

        Menu {
          Button("Bearbeiten", systemImage: "pencil", action: onEdit)
          Divider()
          Button("Löschen", systemImage: "trash", role: .destructive, action: onDelete)
        } label: {
          Image(systemName: "ellipsis.circle")
            .font(.title2)
        }
        .menuStyle(.borderlessButton)
        .frame(width: 32)
        .help("Weitere Aktionen")
      }
    }

    private var metadataCard: some View {
      HStack(spacing: 28) {
        metadataItem("Geändert", detail.modified, icon: "clock")
        metadataItem("Felder", "\(detail.fields.count)", icon: "list.bullet.rectangle")
        metadataItem("Runtime", store.runtime?.version ?? "symvault", icon: "terminal")
        Spacer()
      }
      .padding(16)
      .glassmorphicPanel(cornerRadius: 10, addCorners: false)
    }

    private func metadataItem(_ label: String, _ value: String, icon: String) -> some View {
      HStack(spacing: 8) {
        Image(systemName: icon).foregroundStyle(SymairaTheme.goldPrimary)
        VStack(alignment: .leading, spacing: 1) {
          Text(label).font(.caption2).foregroundStyle(SymairaTheme.textMuted)
          Text(value).font(.caption.weight(.medium)).foregroundStyle(SymairaTheme.textSecondary)
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

    private func label(for field: String) -> String {
      field.replacingOccurrences(of: "_", with: " ").capitalized
    }
  }

  private struct SecretFieldRow: View {
    let field: String
    let value: JSONValue
    @Environment(VaultStore.self) private var store
    @State private var isRevealed = false
    @State private var isHovered = false

    var body: some View {
      HStack(alignment: .center, spacing: 14) {
        Image(systemName: iconName)
          .foregroundStyle(SymairaTheme.goldPrimary)
          .frame(width: 22)

        VStack(alignment: .leading, spacing: 4) {
          Text(label)
            .font(.caption.weight(.semibold))
            .foregroundStyle(SymairaTheme.textMuted)
          if sensitive && !isRevealed {
            fieldValueText.textSelection(.disabled)
          } else {
            fieldValueText.textSelection(.enabled)
          }
        }

        Spacer(minLength: 12)

        if sensitive {
          Button {
            isRevealed.toggle()
          } label: {
            Image(systemName: isRevealed ? "eye.slash" : "eye")
          }
          .buttonStyle(.plain)
          .help(isRevealed ? "Verbergen" : "Anzeigen")
        }

        Button {
          store.copy(value.displayString, label: label)
        } label: {
          Image(systemName: "doc.on.doc")
        }
        .buttonStyle(.plain)
        .help("\(label) kopieren")
      }
      .padding(.horizontal, 18)
      .padding(.vertical, 15)
      .background(isHovered ? Color.white.opacity(0.025) : Color.clear)
      .onHover { isHovered = $0 }
    }

    private var sensitive: Bool { VaultFieldSecurity.isSensitive(field) }

    private var fieldValueText: some View {
      Text(displayValue)
        .font(.body.monospaced())
        .foregroundStyle(SymairaTheme.textPrimary)
        .lineLimit(field == "notes" ? 5 : 2)
    }

    private var displayValue: String {
      guard !sensitive || isRevealed else {
        return String(repeating: "•", count: min(max(value.displayString.count, 8), 20))
      }
      return value.displayString
    }

    private var label: String {
      switch field {
      case "username": return "Benutzername"
      case "password": return "Passwort"
      case "url": return "URL"
      case "notes": return "Notizen"
      case "api_key": return "API Key"
      case "private_key": return "Private Key"
      case "database_url": return "Datenbank-URL"
      default: return field.replacingOccurrences(of: "_", with: " ").capitalized
      }
    }

    private var iconName: String {
      switch field {
      case "username": return "person.fill"
      case "password", "secret", "token", "api_key": return "key.fill"
      case "url", "database_url": return "link"
      case "notes": return "note.text"
      case "totp": return "timer"
      default: return "text.alignleft"
      }
    }
  }

  private struct TOTPCard: View {
    let totp: VaultTOTP
    let loadedAt: Date
    let refresh: () async -> Void
    @Environment(VaultStore.self) private var store

    var body: some View {
      TimelineView(.periodic(from: .now, by: 1)) { context in
        HStack(spacing: 20) {
          ZStack {
            Circle()
              .stroke(Color.white.opacity(0.08), lineWidth: 5)
            Circle()
              .trim(from: 0, to: progress(at: context.date))
              .stroke(SymairaTheme.goldPrimary, style: StrokeStyle(lineWidth: 5, lineCap: .round))
              .rotationEffect(.degrees(-90))
            Text("\(remaining(at: context.date))")
              .font(.caption.monospacedDigit().weight(.semibold))
              .foregroundStyle(SymairaTheme.textSecondary)
          }
          .frame(width: 58, height: 58)

          VStack(alignment: .leading, spacing: 4) {
            Text("Einmalcode")
              .font(.caption.weight(.semibold))
              .foregroundStyle(SymairaTheme.textMuted)
            Text(groupedCode)
              .font(.system(size: 30, weight: .semibold, design: .monospaced))
              .foregroundStyle(SymairaTheme.textPrimary)
              .contentTransition(.numericText())
          }

          Spacer()

          Button {
            store.copy(totp.code, label: "Einmalcode")
          } label: {
            Label("Code kopieren", systemImage: "doc.on.doc.fill")
          }
          .buttonStyle(SymairaSecondaryButtonStyle())
        }
        .padding(18)
        .glassmorphicPanel()
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

    private func progress(at date: Date) -> Double {
      Double(remaining(at: date)) / Double(max(totp.period, 1))
    }
  }
#endif
