import SwiftUI

/// Read-only entry detail. Copy a field to the clipboard; no editing controls
/// per the read-only iOS scope (#868).
struct EntryDetailView: View {
    @EnvironmentObject private var store: VaultStore
    let entry: MobileVaultEntry

    private var sortedFields: [(key: String, value: String)] {
        entry.fields.sorted { $0.key < $1.key }
    }

    var body: some View {
        List {
            Section(entry.path) {
                ForEach(sortedFields, id: \.key) { field in
                    HStack {
                        Text(field.key)
                            .foregroundStyle(.secondary)
                        Spacer()
                        if field.key.lowercased().contains("totp") {
                            Text(field.value)
                                .textSelection(.enabled)
                                .font(.system(.body, design: .monospaced))
                        } else {
                            Text(field.value)
                                .textSelection(.enabled)
                        }
                    }
                    .swipeActions {
                        Button {
                            store.copy(field.value)
                        } label: {
                            Label("Copy", systemImage: "doc.on.doc")
                        }
                    }
                }
            }
        }
        .navigationTitle(entry.fields["username"] ?? "Entry")
        .navigationBarTitleDisplayMode(.inline)
    }
}
