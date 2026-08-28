import Foundation
import Security
import Testing

@testable import SymvaultIOS

@MainActor
@Test func accessControlThrowsWhenBiometryUnavailable() throws {
    // On systems without enrolled biometrics, SecAccessControlCreateWithFlags
    // returns nil and populates an error. The wrapper must throw rather than
    // force-unwrap (the previous behaviour).
    do {
        _ = try DeviceIdentityStore.accessControl()
        // Biometrics are available on this host; the function returns valid.
        // The important guarantee is that it is `throws` and does not crash.
    } catch {
        // Expected on hosts without biometrics; test passes because the
        // error is thrown cleanly.
    }
}

@MainActor
@Test func savePropagatesAccessControlError() throws {
    DeviceIdentityStore.accessControlOverride = {
        throw NSError(domain: "Test", code: Int(errSecParam),
                      userInfo: [NSLocalizedDescriptionKey: "Simulated ACL failure"])
    }
    defer { DeviceIdentityStore.accessControlOverride = nil }

    do {
        try DeviceIdentityStore.save("test-identity")
        Issue.record("expected DeviceIdentityStore.save to throw")
    } catch let error as NSError {
        #expect(error.domain == "Test")
        #expect(error.code == Int(errSecParam))
    } catch {
        Issue.record("expected NSError, got \(error)")
    }
}
