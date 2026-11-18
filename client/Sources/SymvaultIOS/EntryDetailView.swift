import SwiftUI
import SymairaTheme

/// Read-only entry detail. Values are masked until revealed; copy works from
/// the button or the context menu. No editing on iOS (#868).
struct EntryDetailView: View {
    @EnvironmentObject private var store: VaultStore
    let entry: MobileVaultEntry
    @State private var revealed: Set<String> = []
    @State private var copiedField: String?

    private var sortedFields: [(key: String, value: String)] {
        entry.fields.sorted { $0.key < $1.key }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: SymairaSpacing.large) {
                VStack(alignment: .leading, spacing: SymairaSpacing.xSmall) {
                    Text(verbatim: entry.path.split(separator: "/").last.map(String.init) ?? entry.path)
                        .symairaText(.title)
                        .accessibilityAddTraits(.isHeader)
                    Text(verbatim: entry.path).symairaText(.monoSmall).foregroundStyle(SymairaTokens.ink3)
                }
                if let copiedField {
                    SymairaNotice(message: L("%@ copied.", copiedField), tone: .positive)
                }
                SymairaFormSection(L("Fields")) {
                    ForEach(Array(sortedFields.enumerated()), id: \.element.key) { index, field in
                        if index > 0 { SymairaFormDivider() }
                        row(field)
                    }
                }
            }
            .padding(SymairaSpacing.xLarge)
        }
        .background(SymairaTokens.canvas)
        .navigationTitle(entry.fields["username"] ?? L("Entry"))
        .navigationBarTitleDisplayMode(.inline)
    }

    private func row(_ field: (key: String, value: String)) -> some View {
        let sensitive = Self.isSensitive(field.key)
        let shown = !sensitive || revealed.contains(field.key)
        return HStack(alignment: .firstTextBaseline, spacing: SymairaSpacing.small) {
            VStack(alignment: .leading, spacing: SymairaSpacing.xSmall) {
                Text(verbatim: field.key).symairaText(.secondary)
                Group {
                    if shown {
                        Text(verbatim: field.value).textSelection(.enabled)
                    } else {
                        Text(verbatim: String(repeating: "•", count: 12))
                            .accessibilityLabel(L("Hidden value"))
                    }
                }
                .symairaText(.mono)
                .foregroundStyle(SymairaTokens.ink)
            }
            Spacer(minLength: SymairaSpacing.small)
            if sensitive {
                SymairaIconButton(
                    shown ? L("Hide %@", field.key) : L("Show %@", field.key),
                    icon: shown ? .hidden : .visible
                ) {
                    if shown { revealed.remove(field.key) } else { revealed.insert(field.key) }
                }
            }
            SymairaIconButton(L("Copy %@", field.key), icon: .copy) { copy(field) }
        }
        .padding(.vertical, SymairaSpacing.small)
        .contextMenu {
            Button(L("Copy %@", field.key)) { copy(field) }
        }
    }

    private func copy(_ field: (key: String, value: String)) {
        store.copy(field.value)
        copiedField = field.key
    }

    private static func isSensitive(_ key: String) -> Bool {
        let key = key.lowercased()
        return ["password", "secret", "token", "api_key", "private_key", "totp", "certificate", "database_url"]
            .contains { key.contains($0) }
    }
}
