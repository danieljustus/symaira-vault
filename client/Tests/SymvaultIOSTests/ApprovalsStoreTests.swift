import Foundation
import Testing

@testable import SymvaultIOS

/// Records every request it sees and replays canned responses in order.
/// Duplicated from ApprovalDeviceClientTests rather than shared, matching
/// that file's own `private` scoping.
private final class FakeTransport: ApprovalTransport, @unchecked Sendable {
    private(set) var requests: [URLRequest] = []
    private var responses: [(Data, HTTPURLResponse)]

    init(responses: [(Data, HTTPURLResponse)]) {
        self.responses = responses
    }

    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        requests.append(request)
        guard !responses.isEmpty else {
            fatalError("FakeTransport ran out of canned responses")
        }
        return responses.removeFirst()
    }
}

private func emptyApprovalsResponse() -> (Data, HTTPURLResponse) {
    let data = try! JSONSerialization.data(withJSONObject: ["requests": []])
    let response = HTTPURLResponse(url: URL(string: "https://127.0.0.1:1")!, statusCode: 200, httpVersion: nil, headerFields: nil)!
    return (data, response)
}

private func testSession() -> ApprovalSession {
    ApprovalSession(
        token: "tok-1", deviceID: "dev-1", host: "127.0.0.1", port: 1,
        fingerprint: "fp", expiresAt: Date().addingTimeInterval(3600)
    )
}

@MainActor
@Test func refreshReadsTheKeychainOnceAcrossMultipleTicks() async {
    var readCount = 0
    let session = testSession()
    let transport = FakeTransport(responses: [emptyApprovalsResponse(), emptyApprovalsResponse(), emptyApprovalsResponse()])
    let client = ApprovalDeviceClient(transportFactory: { _ in transport })
    let store = ApprovalsStore(client: client)
    store.sessionReader = {
        readCount += 1
        return session
    }

    await store.refresh()
    await store.refresh()
    await store.refresh()

    #expect(readCount == 1)
    #expect(transport.requests.count == 3)
}

@MainActor
@Test func isPairedCachesMissingSessionAcrossViewReads() {
    var readCount = 0
    let store = ApprovalsStore()
    store.sessionReader = {
        readCount += 1
        return nil
    }

    #expect(!store.isPaired)
    #expect(!store.isPaired)
    #expect(readCount == 1)
}

@MainActor
@Test func approveAndDenyReuseTheCachedSessionAfterAFreshRead() async {
    var readCount = 0
    let session = testSession()
    let transport = FakeTransport(responses: [emptyApprovalsResponse(), jsonApproveResponse(), jsonDenyResponse()])
    let client = ApprovalDeviceClient(transportFactory: { _ in transport })
    let store = ApprovalsStore(client: client)
    store.sessionReader = {
        readCount += 1
        return session
    }
    store.biometricAuthenticator = { _ in true }

    // First call (refresh) does the one Keychain read for this run.
    await store.refresh()
    let request = ApprovalRequest(id: "apr-1", agentName: "agent", path: "work/x", write: true, reason: "r", createdAt: Date(), expiresAt: Date(), status: "pending")
    await store.approve(request)
    await store.deny(request)

    #expect(readCount == 1)
}

@MainActor
@Test func pairRefreshesTheCachedSessionWithoutAKeychainRead() async {
    var readCount = 0
    let enrolled = testSession()
    let transport = FakeTransport(responses: [
        jsonEnrollResponse(token: enrolled.token, deviceID: enrolled.deviceID),
        emptyApprovalsResponse(),
    ])
    let client = ApprovalDeviceClient(transportFactory: { _ in transport })
    let store = ApprovalsStore(client: client)
    store.sessionReader = {
        readCount += 1
        return nil
    }

    let payload = ApprovalPairingPayload(host: enrolled.host, port: enrolled.port, code: "CODE", fingerprint: enrolled.fingerprint)
    await store.pair(with: payload, deviceName: "iPhone")
    await store.refresh()

    // pair() populates the cache directly from the enrollment response, so
    // the subsequent refresh() must not need a Keychain read at all.
    #expect(readCount == 0)
    #expect(transport.requests.count == 2)
}

private func jsonEnrollResponse(token: String, deviceID: String) -> (Data, HTTPURLResponse) {
    let body: [String: Any] = ["token": token, "device_id": deviceID, "expires_at": "2026-08-30T12:00:00Z"]
    let data = try! JSONSerialization.data(withJSONObject: body)
    let response = HTTPURLResponse(url: URL(string: "https://127.0.0.1:1")!, statusCode: 200, httpVersion: nil, headerFields: nil)!
    return (data, response)
}

private func jsonApproveResponse() -> (Data, HTTPURLResponse) {
    let data = try! JSONSerialization.data(withJSONObject: [String: Any]())
    let response = HTTPURLResponse(url: URL(string: "https://127.0.0.1:1")!, statusCode: 200, httpVersion: nil, headerFields: nil)!
    return (data, response)
}

private func jsonDenyResponse() -> (Data, HTTPURLResponse) {
    jsonApproveResponse()
}
