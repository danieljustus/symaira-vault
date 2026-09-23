import Darwin
import Foundation
import SymvaultRustCore
import UIKit

@MainActor @objc final class RustCoreSmokeAppDelegate: UIResponder, UIApplicationDelegate {
    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        let identity = symvault_generate_identity()
        guard identity.error.len == 0, identity.output.len > 0 else {
            symvault_buffer_free(identity.output)
            symvault_buffer_free(identity.error)
            exit(1)
        }

        let marker = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("rust-ffi-smoke.pass")
        do {
            try Data("identity-generation-ok\n".utf8).write(to: marker, options: .atomic)
        } catch {
            symvault_buffer_free(identity.output)
            symvault_buffer_free(identity.error)
            exit(2)
        }
        symvault_buffer_free(identity.output)
        symvault_buffer_free(identity.error)
        exit(0)
    }
}

UIApplicationMain(
    CommandLine.argc,
    CommandLine.unsafeArgv,
    nil,
    NSStringFromClass(RustCoreSmokeAppDelegate.self)
)
