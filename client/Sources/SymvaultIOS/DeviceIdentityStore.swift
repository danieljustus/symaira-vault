import Foundation
import Security

/// Keychain storage for the device identity on iOS. The master identity is
/// stored with `ThisDeviceOnly` accessibility (no iCloud sync) and a biometric
/// ACL so it can only be read after a successful Face ID / Touch ID prompt.
@MainActor
enum DeviceIdentityStore {
    static let service = "com.symaira.vault.deviceIdentity"
    static let account = "masterIdentity"

    static func save(_ identity: String) throws {
        let data = Data(identity.utf8)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessControl as String: try Self.accessControl(),
        ]
        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw NSError(domain: "DeviceIdentityStore", code: Int(status),
                          userInfo: [NSLocalizedDescriptionKey: "Could not store device identity (\(status))"])
        }
    }

    static func read() throws -> String {
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
            throw NSError(domain: "DeviceIdentityStore", code: Int(status),
                          userInfo: [NSLocalizedDescriptionKey: "Device identity not available (\(status))"])
        }
        guard let s = String(data: data, encoding: .utf8) else {
            throw NSError(domain: "DeviceIdentityStore", code: -1,
                          userInfo: [NSLocalizedDescriptionKey: "Device identity not readable"])
        }
        return s
    }

    static func clear() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(query as CFDictionary)
    }

    static func accessControl() throws -> SecAccessControl {
        // ThisDeviceOnly + biometric-required: the identity never leaves the
        // device and can only be read after a local biometric prompt.
        var error: Unmanaged<CFError>?
        let flags: SecAccessControlCreateFlags = [.biometryCurrentSet]
        let create = accessControlFactory ?? { flags, error in
            SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                            flags, error)
        }
        guard let ac = create(flags, &error) else {
            let underlying = error?.takeRetainedValue() as Error? ?? NSError(domain: "DeviceIdentityStore", code: Int(errSecParam), userInfo: nil)
            throw NSError(domain: "DeviceIdentityStore",
                          code: Int(errSecParam),
                          userInfo: [NSLocalizedDescriptionKey: "Biometric access control could not be created. Please set a device passcode and enrol Face ID or Touch ID. (\(underlying.localizedDescription))",
                                     NSUnderlyingErrorKey: underlying])
        }
        return ac
    }

    // Test hook for deterministic ACL-creation failures. Nil in production.
    static var accessControlFactory: ((SecAccessControlCreateFlags, UnsafeMutablePointer<Unmanaged<CFError>?>?) -> SecAccessControl?)?
}
