import Foundation
import Security
import Testing

@testable import SymvaultIOS

@MainActor
@Test func accessControlThrowsWhenBiometryUnavailable() throws {
    let underlying = NSError(domain: "TestACL", code: 42,
                             userInfo: [NSLocalizedDescriptionKey: "simulated ACL failure"])
    DeviceIdentityStore.accessControlFactory = { _, error in
        error?.pointee = Unmanaged.passRetained(underlying as! CFError)
        return nil
    }
    defer { DeviceIdentityStore.accessControlFactory = nil }

    do {
        _ = try DeviceIdentityStore.accessControl()
        Issue.record("expected accessControl() to throw")
    } catch {
        let nsError = error as NSError
        #expect(nsError.userInfo[NSUnderlyingErrorKey] as? NSError === underlying)
        #expect(nsError.localizedDescription.contains("simulated ACL failure"))
    }
}

@MainActor
@Test func savePropagatesAccessControlError() throws {
    DeviceIdentityStore.accessControlFactory = { _, error in
        let failure = NSError(domain: "Test", code: Int(errSecParam),
                              userInfo: [NSLocalizedDescriptionKey: "Simulated ACL failure"])
        error?.pointee = Unmanaged.passRetained(failure as! CFError)
        return nil
    }
    defer { DeviceIdentityStore.accessControlFactory = nil }

    do {
        try DeviceIdentityStore.save("test-identity")
        Issue.record("expected DeviceIdentityStore.save to throw")
    } catch let error as NSError {
        #expect(error.userInfo[NSUnderlyingErrorKey] != nil)
        #expect(error.localizedDescription.contains("Simulated ACL failure"))
    } catch {
        Issue.record("expected NSError, got \(error)")
    }
}
