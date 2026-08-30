import Foundation
import LocalAuthentication
import SwiftUI

/// Drives the pending-approvals screen: polls the paired server, and
/// approves/denies requests. Mirrors VaultStore's shape (published state +
/// async methods that set `error` on failure) for consistency with the rest
/// of the app.
@MainActor
final class ApprovalsStore: ObservableObject {
    @Published var pending: [ApprovalRequest] = []
    @Published var isBusy = false
    @Published var error: String?

    private let client: ApprovalDeviceClient
    private var pollTask: Task<Void, Never>?
    private let pollInterval: Duration

    /// Injected so tests can bypass the real LAContext biometric prompt.
    /// Production default performs a real Face ID/Touch ID/passcode check.
    var biometricAuthenticator: (String) async -> Bool = { reason in
        await withCheckedContinuation { continuation in
            let context = LAContext()
            context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, _ in
                continuation.resume(returning: success)
            }
        }
    }

    init(client: ApprovalDeviceClient = ApprovalDeviceClient(), pollInterval: Duration = .seconds(4)) {
        self.client = client
        self.pollInterval = pollInterval
    }

    var isPaired: Bool {
        (try? ApprovalSessionStore.read()) != nil
    }

    func pair(with payload: ApprovalPairingPayload, deviceName: String) async {
        isBusy = true
        error = nil
        defer { isBusy = false }
        do {
            let session = try await client.enroll(payload: payload, deviceName: deviceName)
            try ApprovalSessionStore.save(session)
        } catch {
            self.error = error.localizedDescription
        }
    }

    func startPolling() {
        stopPolling()
        pollTask = Task { [weak self] in
            while let self, !Task.isCancelled {
                await self.refresh()
                try? await Task.sleep(for: self.pollInterval)
            }
        }
    }

    func stopPolling() {
        pollTask?.cancel()
        pollTask = nil
    }

    func refresh() async {
        guard let session = try? ApprovalSessionStore.read() else {
            pending = []
            return
        }
        do {
            pending = try await client.fetchPendingApprovals(session: session)
        } catch {
            self.error = error.localizedDescription
        }
    }

    /// Approves a pending request. Requires a fresh biometric confirmation —
    /// matches the issue's "Face ID to approve" scope; deny does not gate on
    /// biometrics since it grants nothing.
    func approve(_ request: ApprovalRequest) async {
        guard let session = try? ApprovalSessionStore.read() else { return }
        let reason = "Approve \(request.agentName)'s request to \(request.write ? "write" : "read") \(request.path)"
        guard await biometricAuthenticator(reason) else { return }
        await decide(session: session, request: request, approve: true)
    }

    func deny(_ request: ApprovalRequest) async {
        guard let session = try? ApprovalSessionStore.read() else { return }
        await decide(session: session, request: request, approve: false)
    }

    private func decide(session: ApprovalSession, request: ApprovalRequest, approve: Bool) async {
        isBusy = true
        error = nil
        defer { isBusy = false }
        do {
            try await client.decide(session: session, requestID: request.id, approve: approve)
            pending.removeAll { $0.id == request.id }
        } catch {
            self.error = error.localizedDescription
        }
    }
}
