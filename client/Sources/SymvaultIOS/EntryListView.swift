import SwiftUI
import SymairaTheme

/// Read-only browse list. Selecting an entry shows its detail (copy enabled).
struct EntryListView: View {
    @EnvironmentObject private var store: VaultStore
    @State private var searchText = ""

    var body: some View {
        NavigationStack {
            content
                .navigationTitle(L("Vault"))
                .navigationDestination(for: MobileVaultEntry.self) { entry in
                    EntryDetailView(entry: entry)
                }
                .searchable(text: $searchText, prompt: L("Search entries"))
                .refreshable { await store.loadEntries() }
                .background(SymairaTokens.canvas)
        }
    }

    @ViewBuilder
    private var content: some View {
        if store.isBusy && store.entries.isEmpty {
            SymairaLoadingState(L("Loading entries…"))
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if let error = store.error, store.entries.isEmpty {
            VStack(spacing: SymairaSpacing.large) {
                SymairaNotice(title: L("Entries Not Loaded"), message: error, tone: .critical)
                Button(L("Try Again")) { Task { await store.loadEntries() } }
                    .symairaButtonStyle(.secondary)
            }
            .padding(SymairaSpacing.xLarge)
            .frame(maxHeight: .infinity, alignment: .top)
        } else if filtered.isEmpty {
            SymairaEmptyState(
                icon: searchText.isEmpty ? .key : .search,
                title: searchText.isEmpty ? L("No Entries") : L("No Matching Entries"),
                message: searchText.isEmpty
                    ? L("Entries shared with this iPhone appear here. Add this device as a recipient on your Mac.")
                    : L("Try part of the path instead.")
            )
            .padding(SymairaSpacing.xLarge)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            List(filtered) { entry in
                NavigationLink(value: entry) {
                    VStack(alignment: .leading, spacing: SymairaSpacing.xSmall) {
                        Text(verbatim: entry.path).symairaText(.bodyEmphasized)
                        if let user = entry.fields["username"] {
                            Text(verbatim: user).symairaText(.secondary)
                        }
                    }
                    .padding(.vertical, SymairaSpacing.xSmall)
                }
                .listRowBackground(SymairaTokens.surface)
            }
            .scrollContentBackground(.hidden)
        }
    }

    private var filtered: [MobileVaultEntry] {
        guard !searchText.isEmpty else { return store.entries }
        return store.entries.filter { $0.path.localizedCaseInsensitiveContains(searchText) }
    }
}
