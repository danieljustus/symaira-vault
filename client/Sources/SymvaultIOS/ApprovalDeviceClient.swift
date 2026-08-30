import CryptoKit
import Foundation
import Security

/// Errors surfaced by ApprovalDeviceClient. All are user-facing (shown via
/// VaultStore-style `.error` propagation), so keep messages plain.
enum ApprovalClientError: LocalizedError {
    case invalidResponse
    case server(String)

    var errorDescription: String? {
        switch self {
        case .invalidResponse:
            return "The server returned an unexpected response."
        case .server(let message):
            return message
        }
    }
}

/// Computes and compares certificate fingerprints for pinning. Kept
/// separate from the URLSessionDelegate glue so the actual accept/reject
/// decision is a pure function, testable without a real TLS handshake.
enum CertificatePinning {
    /// Returns the lowercase hex SHA-256 fingerprint of a certificate's DER
    /// encoding — the same value `internal/mcp/serverbootstrap.CertFingerprint`
    /// computes on the Go side, so the two must always agree.
    static func fingerprint(of certificate: SecCertificate) -> String {
        let data = SecCertificateCopyData(certificate) as Data
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    /// Reports whether `certificate`'s fingerprint matches `expected`
    /// (case-insensitive). This is the entire trust decision for a pinned
    /// connection — callers must fail closed (reject) on `false`, never
    /// fall back to system trust evaluation.
    static func matches(_ certificate: SecCertificate, expected: String) -> Bool {
        fingerprint(of: certificate) == expected.lowercased()
    }
}

/// A URLSessionDelegate that pins a connection to one exact certificate
/// fingerprint, ignoring standard hostname/CA validation. This is
/// deliberate: the server's self-signed certificate only covers loopback
/// SANs, and the trust anchor here is the fingerprint the user scanned from
/// a physically-displayed QR code, not a certificate authority. Any
/// mismatch fails the handshake — there is no fallback to system trust.
final class PinnedSessionDelegate: NSObject, URLSessionDelegate, @unchecked Sendable {
    private let expectedFingerprint: String

    init(expectedFingerprint: String) {
        self.expectedFingerprint = expectedFingerprint
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust,
              let chain = SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate],
              let leaf = chain.first,
              CertificatePinning.matches(leaf, expected: expectedFingerprint)
        else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        completionHandler(.useCredential, URLCredential(trust: serverTrust))
    }
}

/// The minimal networking seam ApprovalDeviceClient depends on, so tests
/// can assert on request shape without opening real sockets. The production
/// implementation wraps a URLSession configured with PinnedSessionDelegate;
/// tests substitute a closure-based fake.
protocol ApprovalTransport: Sendable {
    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse)
}

/// Production transport: a pinned URLSession per call, since each call may
/// target a different fingerprint (enrollment happens before a session
/// exists) and URLSessionDelegate is fixed at session-creation time.
struct URLSessionApprovalTransport: ApprovalTransport {
    let fingerprint: String

    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let delegate = PinnedSessionDelegate(expectedFingerprint: fingerprint)
        let session = URLSession(configuration: .ephemeral, delegate: delegate, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw ApprovalClientError.invalidResponse
        }
        return (data, http)
    }
}

/// Talks to the approval-device HTTP surface (`internal/approval`): device
/// enrollment, listing pending requests, and approving/denying them. Every
/// call is over a connection pinned to the fingerprint supplied at
/// construction — there is no unpinned code path.
struct ApprovalDeviceClient: @unchecked Sendable {
    private let transportFactory: @Sendable (String) -> any ApprovalTransport
    private let decoder: JSONDecoder
    private let encoder: JSONEncoder

    init(transportFactory: @escaping @Sendable (String) -> any ApprovalTransport = { URLSessionApprovalTransport(fingerprint: $0) }) {
        self.transportFactory = transportFactory
        self.decoder = Self.makeDecoder()
        self.encoder = JSONEncoder()
    }

    private static func makeDecoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { decoder in
            let container = try decoder.singleValueContainer()
            let raw = try container.decode(String.self)
            // Formatters are created fresh here (not captured from an outer
            // scope) so this closure — which JSONDecoder requires to be
            // @Sendable — never crosses a non-Sendable value across an
            // isolation boundary.
            let withFraction = ISO8601DateFormatter()
            withFraction.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            if let date = withFraction.date(from: raw) { return date }
            let plain = ISO8601DateFormatter()
            plain.formatOptions = [.withInternetDateTime]
            if let date = plain.date(from: raw) { return date }
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Unrecognized date format: \(raw)")
        }
        return decoder
    }

    private func baseURL(host: String, port: Int) -> String {
        "https://\(host):\(port)"
    }

    /// Exchanges a pairing code (scanned or typed from the QR payload) for a
    /// long-lived device session, via `POST /api/v1/devices/enroll`.
    func enroll(payload: ApprovalPairingPayload, deviceName: String) async throws -> ApprovalSession {
        guard let url = URL(string: baseURL(host: payload.host, port: payload.port) + "/api/v1/devices/enroll") else {
            throw ApprovalClientError.invalidResponse
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try encoder.encode([
            "code": payload.code,
            "device_name": deviceName,
            "public_key": "",
        ])

        let (data, response) = try await transportFactory(payload.fingerprint).send(request)
        try Self.checkStatus(response, data: data, decoder: decoder)
        let decoded = try decoder.decode(ApprovalEnrollResponse.self, from: data)
        return ApprovalSession(
            token: decoded.token,
            deviceID: decoded.deviceID,
            host: payload.host,
            port: payload.port,
            fingerprint: payload.fingerprint,
            expiresAt: decoded.expiresAt
        )
    }

    /// Lists pending approval requests via `GET /api/v1/approvals`.
    func fetchPendingApprovals(session: ApprovalSession) async throws -> [ApprovalRequest] {
        guard let url = URL(string: baseURL(host: session.host, port: session.port) + "/api/v1/approvals") else {
            throw ApprovalClientError.invalidResponse
        }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("Bearer \(session.token)", forHTTPHeaderField: "Authorization")

        let (data, response) = try await transportFactory(session.fingerprint).send(request)
        try Self.checkStatus(response, data: data, decoder: decoder)
        let decoded = try decoder.decode(PendingApprovalsResponse.self, from: data)
        return decoded.requests
    }

    /// Approves or denies one pending request via
    /// `POST /api/v1/approvals/{id}/approve|deny`.
    func decide(session: ApprovalSession, requestID: String, approve: Bool) async throws {
        let action = approve ? "approve" : "deny"
        guard let url = URL(string: baseURL(host: session.host, port: session.port) + "/api/v1/approvals/\(requestID)/\(action)") else {
            throw ApprovalClientError.invalidResponse
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("Bearer \(session.token)", forHTTPHeaderField: "Authorization")

        let (data, response) = try await transportFactory(session.fingerprint).send(request)
        try Self.checkStatus(response, data: data, decoder: decoder)
    }

    private static func checkStatus(_ response: HTTPURLResponse, data: Data, decoder: JSONDecoder) throws {
        guard (200...299).contains(response.statusCode) else {
            if let apiError = try? decoder.decode(APIErrorResponse.self, from: data) {
                throw ApprovalClientError.server(apiError.error)
            }
            throw ApprovalClientError.server("Request failed with status \(response.statusCode).")
        }
    }
}

private struct PendingApprovalsResponse: Codable {
    let requests: [ApprovalRequest]
}

private struct APIErrorResponse: Codable {
    let error: String
}
