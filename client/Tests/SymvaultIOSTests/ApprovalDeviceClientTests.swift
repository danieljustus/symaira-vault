import Foundation
import Testing

@testable import SymvaultIOS

/// Records every request it sees and replays canned responses in order.
/// Marked @unchecked Sendable: tests drive it sequentially with `await`, so
/// there is no real concurrent access despite the protocol requiring
/// Sendable for production use across actor boundaries.
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

private func jsonResponse(_ status: Int, _ body: [String: Any]) -> (Data, HTTPURLResponse) {
    let data = try! JSONSerialization.data(withJSONObject: body)
    let response = HTTPURLResponse(url: URL(string: "https://127.0.0.1:1")!, statusCode: status, httpVersion: nil, headerFields: nil)!
    return (data, response)
}

@Test func enrollSendsExpectedRequestAndParsesResponse() async throws {
    let transport = FakeTransport(responses: [
        jsonResponse(200, ["token": "tok-abc", "device_id": "dev-1", "expires_at": "2026-08-30T12:00:00Z"]),
    ])
    let client = ApprovalDeviceClient(transportFactory: { _ in transport })
    let payload = ApprovalPairingPayload(host: "192.168.1.42", port: 8443, code: "CODE123", fingerprint: "fp-1")

    let session = try await client.enroll(payload: payload, deviceName: "iPhone")

    #expect(session.token == "tok-abc")
    #expect(session.deviceID == "dev-1")
    #expect(session.host == "192.168.1.42")
    #expect(session.port == 8443)
    #expect(session.fingerprint == "fp-1")

    #expect(transport.requests.count == 1)
    let request = transport.requests[0]
    #expect(request.httpMethod == "POST")
    #expect(request.url?.absoluteString == "https://192.168.1.42:8443/api/v1/devices/enroll")
    let body = try #require(request.httpBody)
    let decoded = try JSONSerialization.jsonObject(with: body) as? [String: String]
    #expect(decoded?["code"] == "CODE123")
    #expect(decoded?["device_name"] == "iPhone")
}

@Test func enrollThrowsServerErrorMessage() async throws {
    let transport = FakeTransport(responses: [
        jsonResponse(401, ["error": "invalid or expired pairing code"]),
    ])
    let client = ApprovalDeviceClient(transportFactory: { _ in transport })
    let payload = ApprovalPairingPayload(host: "127.0.0.1", port: 1, code: "bad", fingerprint: "fp")

    await #expect(throws: ApprovalClientError.self) {
        _ = try await client.enroll(payload: payload, deviceName: "iPhone")
    }
}

@Test func fetchPendingApprovalsSendsBearerTokenAndParsesEntries() async throws {
    let transport = FakeTransport(responses: [
        jsonResponse(200, [
            "requests": [
                [
                    "ID": "apr-1",
                    "AgentName": "agent-a",
                    "Path": "work/creds",
                    "Write": true,
                    "Reason": "test",
                    "CreatedAt": "2026-08-30T12:00:00.123456+02:00",
                    "ExpiresAt": "2026-08-30T12:05:00Z",
                    "Status": "pending",
                ],
            ],
        ]),
    ])
    let client = ApprovalDeviceClient(transportFactory: { _ in transport })
    let session = ApprovalSession(token: "tok-1", deviceID: "dev-1", host: "127.0.0.1", port: 8443, fingerprint: "fp-1", expiresAt: Date())

    let pending = try await client.fetchPendingApprovals(session: session)

    #expect(pending.count == 1)
    #expect(pending[0].id == "apr-1")
    #expect(pending[0].agentName == "agent-a")
    #expect(pending[0].path == "work/creds")
    #expect(pending[0].write == true)

    let request = transport.requests[0]
    #expect(request.httpMethod == "GET")
    #expect(request.url?.absoluteString == "https://127.0.0.1:8443/api/v1/approvals")
    #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer tok-1")
}

@Test func decideSendsApproveAndDenyToCorrectPaths() async throws {
    let transport = FakeTransport(responses: [jsonResponse(200, [:]), jsonResponse(200, [:])])
    let client = ApprovalDeviceClient(transportFactory: { _ in transport })
    let session = ApprovalSession(token: "tok-1", deviceID: "dev-1", host: "127.0.0.1", port: 1, fingerprint: "fp", expiresAt: Date())

    try await client.decide(session: session, requestID: "apr-1", approve: true)
    try await client.decide(session: session, requestID: "apr-1", approve: false)

    #expect(transport.requests[0].url?.absoluteString == "https://127.0.0.1:1/api/v1/approvals/apr-1/approve")
    #expect(transport.requests[1].url?.absoluteString == "https://127.0.0.1:1/api/v1/approvals/apr-1/deny")
    #expect(transport.requests[0].httpMethod == "POST")
}

@Test func sessionCacheReusesTheSameSessionForTheSameFingerprint() async {
    let cache = URLSessionCache()

    let first = await cache.session(for: "fp-1")
    let second = await cache.session(for: "fp-1")

    #expect(first === second)
}

@Test func sessionCacheCreatesDistinctSessionsForDifferentFingerprints() async {
    let cache = URLSessionCache()

    let first = await cache.session(for: "fp-1")
    let second = await cache.session(for: "fp-2")

    #expect(first !== second)
}

@Test func sessionCacheInvalidateAllDropsCachedSessions() async {
    let cache = URLSessionCache()

    let first = await cache.session(for: "fp-1")
    await cache.invalidateAll()
    let second = await cache.session(for: "fp-1")

    #expect(first !== second)
}
