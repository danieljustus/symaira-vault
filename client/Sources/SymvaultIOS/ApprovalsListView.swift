import SwiftUI
import SymairaTheme

/// The approvals tab: a pairing prompt while no approval device is enrolled,
/// otherwise the live list of pending agent requests with Face-ID-gated
/// approve and plain deny actions.
struct ApprovalsListView: View {
    @EnvironmentObject private var approvalsStore: ApprovalsStore
    @State private var showPairing = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: SymairaSpacing.medium) {
                    if let error = approvalsStore.error {
                        SymairaNotice(message: error, tone: .critical) { approvalsStore.error = nil }
                    }
                    content
                }
                .padding(SymairaSpacing.xLarge)
            }
            .background(SymairaTokens.canvas)
            .navigationTitle(L("Approvals"))
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
        }
    }

    @ViewBuilder
    private var content: some View {
        if !approvalsStore.isPaired {
            SymairaEmptyState(
                icon: .device,
                title: L("Not Paired"),
                message: L("Pair this iPhone as an approval device to approve or deny agent credential requests.")
            ) {
                Button(L("Pair Device")) { showPairing = true }
                    .symairaButtonStyle(.primary)
            }
            .frame(maxWidth: .infinity)
        } else {
            if approvalsStore.pending.isEmpty {
                SymairaEmptyState(
                    icon: .shieldCheck,
                    title: L("No Pending Requests"),
                    message: L("Requests from your agents appear here while they wait for you.")
                )
                .frame(maxWidth: .infinity)
            } else {
                ForEach(approvalsStore.pending) { request in
                    ApprovalRow(request: request)
                }
            }
            pairingSection
        }
    }

    /// Where this device is paired, with a way out when that Mac is no
    /// longer reachable (TestFlight feedback: no way to pair again).
    private var pairingSection: some View {
        SymairaFormSection(
            L("Pairing"),
            footer: L("If your Mac's address changed or the connection keeps failing, pair again with a new code from your Mac.")
        ) {
            SymairaFormRow(L("Paired Mac")) {
                Text(verbatim: approvalsStore.pairedServer ?? "")
                    .symairaText(.monoSmall)
                    .foregroundStyle(SymairaTokens.ink2)
            }
            SymairaFormDivider()
            HStack(spacing: SymairaSpacing.medium) {
                Button(role: .destructive) { approvalsStore.unpair() } label: {
                    Text(L("Remove Pairing")).frame(maxWidth: .infinity)
                }
                .symairaButtonStyle(.secondary)
                Button { showPairing = true } label: {
                    Text(L("Pair Again")).frame(maxWidth: .infinity)
                }
                .symairaButtonStyle(.primary)
            }
            .padding(.vertical, SymairaSpacing.small)
        }
    }
}

private struct ApprovalRow: View {
    @EnvironmentObject private var approvalsStore: ApprovalsStore
    let request: ApprovalRequest

    var body: some View {
        VStack(alignment: .leading, spacing: SymairaSpacing.small) {
            HStack(alignment: .firstTextBaseline) {
                Text(verbatim: request.agentName).symairaText(.heading)
                Spacer()
                SymairaBadge(
                    request.write ? L("Write") : L("Read"),
                    tone: request.write ? .warning : .neutral,
                    icon: request.write ? .edit : .visible
                )
            }
            Text(verbatim: request.path).symairaText(.monoSmall).foregroundStyle(SymairaTokens.ink2)
            if !request.reason.isEmpty {
                Text(verbatim: request.reason).symairaText(.secondary)
            }
            HStack(spacing: SymairaSpacing.medium) {
                Button(L("Deny"), role: .destructive) {
                    Task { await approvalsStore.deny(request) }
                }
                .symairaButtonStyle(.secondary)
                Button(L("Approve")) {
                    Task { await approvalsStore.approve(request) }
                }
                .symairaButtonStyle(.primary)
            }
            .disabled(approvalsStore.isBusy)
            .padding(.top, SymairaSpacing.xSmall)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .symairaCard()
        .accessibilityElement(children: .contain)
    }
}
