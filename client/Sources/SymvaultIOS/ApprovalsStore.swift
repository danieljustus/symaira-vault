import Foundation
import LocalAuthentication
import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

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
    /// Poll interval used while the app is backgrounded. Wider than
    /// `pollInterval` since there is no screen to update and a pending
    /// approval request already carries a 5-minute server-side TTL
    /// (internal/approval/queue.go's DefaultTTL) — polling every 4s while
    /// backgrounded would burn battery/radio for no benefit within that
    /// window.
    private let backgroundPollInterval: Duration

    /// The enrolled session. Read from the Keychain once — on the first
    /// need after `startPolling()` or a fresh `pair()` — rather than on
    /// every poll tick or decision, since SecItemCopyMatching is not free
    /// and this runs every few seconds. Reset only by a new `pair()`; there
    /// is currently no in-app "unpair" flow to also reset it.
    private var cachedSession: ApprovalSession?
    private var hasLoadedSession = false

    /// Injected so tests can count/stub Keychain reads instead of hitting
    /// the real Keychain on every call. Mirrors `biometricAuthenticator`.
    var sessionReader: () -> ApprovalSession? = { try? ApprovalSessionStore.read() }

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

    init(
        client: ApprovalDeviceClient = ApprovalDeviceClient(),
        pollInterval: Duration = .seconds(4),
        backgroundPollInterval: Duration = .seconds(20)
    ) {
        self.client = client
        self.pollInterval = pollInterval
        self.backgroundPollInterval = backgroundPollInterval
    }

    var isPaired: Bool {
        currentSession() != nil
    }

    func pair(with payload: ApprovalPairingPayload, deviceName: String) async {
        isBusy = true
        error = nil
        defer { isBusy = false }
        do {
            let session = try await client.enroll(payload: payload, deviceName: deviceName)
            try ApprovalSessionStore.save(session)
            cachedSession = session
            hasLoadedSession = true
        } catch {
            self.error = error.localizedDescription
        }
    }

    func startPolling() {
        stopPolling()
        cachedSession = sessionReader()
        hasLoadedSession = true
        pollTask = Task { [weak self] in
            while let self, !Task.isCancelled {
                await self.refresh()
                #if canImport(UIKit)
                let backgrounded = UIApplication.shared.applicationState == .background
                #else
                let backgrounded = false
                #endif
                let interval = backgrounded ? self.backgroundPollInterval : self.pollInterval
                try? await Task.sleep(for: interval)
            }
        }
    }

    func stopPolling() {
        pollTask?.cancel()
        pollTask = nil
    }

    func refresh() async {
        guard let session = currentSession() else {
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
        guard let session = currentSession() else { return }
        let reason = "Approve \(request.agentName)'s request to \(request.write ? "write" : "read") \(request.path)"
        guard await biometricAuthenticator(reason) else { return }
        await decide(session: session, request: request, approve: true)
    }

    func deny(_ request: ApprovalRequest) async {
        guard let session = currentSession() else { return }
        await decide(session: session, request: request, approve: false)
    }

    /// Returns the cached session, reading the Keychain only if nothing is
    /// cached yet (e.g. a manual `refresh()`/`approve()`/`deny()` call
    /// before `startPolling()` has run).
    private func currentSession() -> ApprovalSession? {
        if hasLoadedSession {
            return cachedSession
        }
        let session = sessionReader()
        cachedSession = session
        hasLoadedSession = true
        return session
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
