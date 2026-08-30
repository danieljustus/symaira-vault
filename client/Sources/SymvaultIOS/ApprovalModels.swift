import Foundation

/// A pending (or decided) agent credential request, as returned by
/// `GET /api/v1/approvals`. Field names match the Go `approval.Entry`
/// struct's default (untagged) JSON encoding — PascalCase, not snake_case.
struct ApprovalRequest: Identifiable, Codable, Equatable {
    let id: String
    let agentName: String
    let path: String
    let write: Bool
    let reason: String
    let createdAt: Date
    let expiresAt: Date
    let status: String

    enum CodingKeys: String, CodingKey {
        case id = "ID"
        case agentName = "AgentName"
        case path = "Path"
        case write = "Write"
        case reason = "Reason"
        case createdAt = "CreatedAt"
        case expiresAt = "ExpiresAt"
        case status = "Status"
    }
}

/// The pairing payload scanned from (or manually entered from) the QR code
/// shown by `symvault device approval-pair`. Carries the entire trust story
/// for the connection: where to reach the server, the one-time code to
/// redeem, and the certificate fingerprint to pin to.
struct ApprovalPairingPayload: Codable, Equatable {
    let host: String
    let port: Int
    let code: String
    let fingerprint: String
}

/// An enrolled approval-device session, persisted in the Keychain via
/// ApprovalSessionStore. Everything a subsequent request needs to reach and
/// authenticate against the paired server.
struct ApprovalSession: Codable, Equatable {
    let token: String
    let deviceID: String
    let host: String
    let port: Int
    let fingerprint: String
    let expiresAt: Date
}

/// The response body of `POST /api/v1/devices/enroll`.
struct ApprovalEnrollResponse: Codable, Equatable {
    let token: String
    let deviceID: String
    let expiresAt: Date

    enum CodingKeys: String, CodingKey {
        case token
        case deviceID = "device_id"
        case expiresAt = "expires_at"
    }
}
