import Foundation
import Security

/// Keychain storage for the enrolled approval-device session. Unlike
/// DeviceIdentityStore's master identity, this item deliberately has NO
/// biometric ACL: ApprovalsStore polls it every few seconds in the
/// background, and a biometric-gated read would prompt Face ID on every
/// poll. Face ID gating happens instead at the moment of approving a
/// request (see ApprovalsStore.approve), not at reading this session.
@MainActor
enum ApprovalSessionStore {
    static let service = "com.symaira.vault.approvalSession"
    static let account = "session"

    static func save(_ session: ApprovalSession) throws {
        let data = try JSONEncoder().encode(session)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw NSError(domain: "ApprovalSessionStore", code: Int(status),
                          userInfo: [NSLocalizedDescriptionKey: "Could not store approval session (\(status))"])
        }
    }

    static func read() throws -> ApprovalSession {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else {
            throw NSError(domain: "ApprovalSessionStore", code: Int(status),
                          userInfo: [NSLocalizedDescriptionKey: "No approval session available (\(status))"])
        }
        return try JSONDecoder().decode(ApprovalSession.self, from: data)
    }

    static func clear() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(query as CFDictionary)
    }
}
