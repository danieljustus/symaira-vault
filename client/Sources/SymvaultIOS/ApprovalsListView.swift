import SwiftUI

/// The pending-approvals screen: either a pairing prompt (no approval
/// device enrolled yet) or the live list of pending agent requests, with
/// Face-ID-gated approve and plain deny actions.
struct ApprovalsListView: View {
    @EnvironmentObject private var approvalsStore: ApprovalsStore
    @State private var showPairing = false

    var body: some View {
        NavigationStack {
            Group {
                if !approvalsStore.isPaired {
                    ContentUnavailableView {
                        Label("Not Paired", systemImage: "iphone.and.arrow.forward")
                    } description: {
                        Text("Pair this phone as an approval device to approve or deny agent credential requests.")
                    } actions: {
                        Button("Pair Device") { showPairing = true }
                            .buttonStyle(.borderedProminent)
                    }
                } else if approvalsStore.pending.isEmpty {
                    ContentUnavailableView("No Pending Requests", systemImage: "checkmark.shield")
                } else {
                    List(approvalsStore.pending) { request in
                        ApprovalRow(request: request)
                    }
                }
            }
            .navigationTitle("Approvals")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    if approvalsStore.isBusy { ProgressView().controlSize(.small) }
                }
            }
            .refreshable { await approvalsStore.refresh() }
            .task { if approvalsStore.isPaired { approvalsStore.startPolling() } }
            .onDisappear { approvalsStore.stopPolling() }
            .sheet(isPresented: $showPairing) {
                PairingScanView()
                    .environmentObject(approvalsStore)
                    .onDisappear {
                        if approvalsStore.isPaired { approvalsStore.startPolling() }
                    }
            }
            .alert("Error", isPresented: Binding(
                get: { approvalsStore.error != nil },
                set: { if !$0 { approvalsStore.error = nil } }
            )) {
                Button("OK", role: .cancel) {}
            } message: {
                Text(approvalsStore.error ?? "")
            }
        }
    }
}

private struct ApprovalRow: View {
    @EnvironmentObject private var approvalsStore: ApprovalsStore
    let request: ApprovalRequest

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(request.agentName)
                .font(.headline)
            Text(request.path)
                .font(.subheadline)
                .foregroundStyle(.secondary)
            if !request.reason.isEmpty {
                Text(request.reason)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            HStack {
                Label(request.write ? "Write" : "Read", systemImage: request.write ? "pencil" : "eye")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Deny", role: .destructive) {
                    Task { await approvalsStore.deny(request) }
                }
                .buttonStyle(.bordered)
                Button("Approve") {
                    Task { await approvalsStore.approve(request) }
                }
                .buttonStyle(.borderedProminent)
            }
        }
        .padding(.vertical, 4)
    }
}
