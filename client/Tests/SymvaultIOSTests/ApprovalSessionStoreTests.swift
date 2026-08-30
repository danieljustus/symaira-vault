import Foundation
import Testing

@testable import SymvaultIOS

/// Spike: confirms a non-biometric-ACL Keychain item round-trips in the SPM
/// test sandbox on this host, before ApprovalsStore is built on top of that
/// assumption. Unlike DeviceIdentityStore's biometric-gated item (which can
/// only be tested via failure injection), ApprovalSessionStore uses
/// kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly with no biometry flag,
/// so a real save/read/clear should not require any UI interaction.
@MainActor
@Test func approvalSessionStoreRoundTrips() throws {
    ApprovalSessionStore.clear()
    defer { ApprovalSessionStore.clear() }

    let session = ApprovalSession(
        token: "tok-123",
        deviceID: "dev-abc",
        host: "192.168.1.42",
        port: 8443,
        fingerprint: "deadbeef",
        expiresAt: Date(timeIntervalSince1970: 1_800_000_000)
    )
    try ApprovalSessionStore.save(session)

    let read = try ApprovalSessionStore.read()
    #expect(read == session)
}

@MainActor
@Test func approvalSessionStoreReadFailsWhenEmpty() {
    ApprovalSessionStore.clear()
    #expect(throws: (any Error).self) {
        try ApprovalSessionStore.read()
    }
}

@MainActor
@Test func approvalSessionStoreClearRemovesSession() throws {
    let session = ApprovalSession(
        token: "tok-123", deviceID: "dev-abc", host: "127.0.0.1", port: 1,
        fingerprint: "fp", expiresAt: Date()
    )
    try ApprovalSessionStore.save(session)
    ApprovalSessionStore.clear()
    #expect(throws: (any Error).self) {
        try ApprovalSessionStore.read()
    }
}

@MainActor
@Test func approvalSessionStoreOverwritesExistingSession() throws {
    defer { ApprovalSessionStore.clear() }
    let first = ApprovalSession(
        token: "tok-1", deviceID: "dev-1", host: "127.0.0.1", port: 1,
        fingerprint: "fp1", expiresAt: Date()
    )
    let second = ApprovalSession(
        token: "tok-2", deviceID: "dev-2", host: "127.0.0.1", port: 2,
        fingerprint: "fp2", expiresAt: Date()
    )
    try ApprovalSessionStore.save(first)
    try ApprovalSessionStore.save(second)

    let read = try ApprovalSessionStore.read()
    #expect(read == second)
}
