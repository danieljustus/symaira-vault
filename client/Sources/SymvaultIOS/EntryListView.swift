import SwiftUI

/// Read-only browse list. Selecting an entry shows its detail (copy enabled).
struct EntryListView: View {
    @EnvironmentObject private var store: VaultStore

    var body: some View {
        NavigationStack {
            List(store.entries) { entry in
                NavigationLink(value: entry) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(entry.path)
                            .font(.headline)
                        if let user = entry.fields["username"] {
                            Text(user)
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
            .navigationTitle("Vault")
            .navigationDestination(for: MobileVaultEntry.self) { entry in
                EntryDetailView(entry: entry)
            }
            .overlay {
                if store.entries.isEmpty && !store.isBusy {
                    ContentUnavailableView("No entries", systemImage: "tray")
                }
            }
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    if store.isBusy { ProgressView().controlSize(.small) }
                }
            }
            .refreshable { await store.loadEntries() }
        }
    }
}
