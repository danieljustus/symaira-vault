import SwiftUI

/// Read-only browse list. Selecting an entry shows its detail (copy enabled).
struct EntryListView: View {
    @EnvironmentObject private var store: VaultStore
    @EnvironmentObject private var approvalsStore: ApprovalsStore
    @State private var showApprovals = false

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
                ToolbarItem(placement: .topBarLeading) {
                    Button {
                        showApprovals = true
                    } label: {
                        ZStack(alignment: .topTrailing) {
                            Image(systemName: "checkmark.shield")
                            if approvalsStore.pending.count > 0 {
                                Text("\(approvalsStore.pending.count)")
                                    .font(.caption2.bold())
                                    .foregroundStyle(.white)
                                    .padding(3)
                                    .background(Circle().fill(.red))
                                    .offset(x: 10, y: -8)
                            }
                        }
                    }
                    .accessibilityLabel("Approvals")
                }
            }
            .refreshable { await store.loadEntries() }
            .sheet(isPresented: $showApprovals) {
                ApprovalsListView()
                    .environmentObject(approvalsStore)
            }
        }
    }
}
