import Foundation
import SwiftUI
import Combine

/// Read-only iOS vault store. Talks to the embedded `Vaultcore` framework via
/// `MobileVaultCore` (iOS cannot spawn the `symvault` subprocess). Per issue
/// #868 the iOS client is browse/read/copy only — no writes.
@MainActor
final class VaultStore: ObservableObject {
    @Published var isUnlocked = false
    @Published var isBusy = false
    @Published var entries: [MobileVaultEntry] = []
    @Published var selected: MobileVaultEntry?
    @Published var error: String?

    /// Directory of the enrolled vault, shared with the Mac via iCloud Drive
    /// per ADR 0006 D3. Falls back to the app container for local testing.
    let vaultDirectory: URL

    private var core: MobileVaultCore?

    init() {
        if let icloud = FileManager.default.url(forUbiquityContainerIdentifier: nil) {
            vaultDirectory = icloud.appendingPathComponent("Documents/symaira-vault")
        } else {
            vaultDirectory = FileManager.default
                .urls(for: .documentDirectory, in: .userDomainMask)[0]
                .appendingPathComponent("symaira-vault")
        }
        try? FileManager.default.createDirectory(at: vaultDirectory, withIntermediateDirectories: true)
    }

    var isEnrolled: Bool {
        UserDefaults.standard.bool(forKey: "deviceEnrolled")
    }

    func enroll() async {
        isBusy = true
        error = nil
        defer { isBusy = false }
        do {
            let identity = try MobileVaultCore(vaultDirectory: vaultDirectory).generateIdentity()
            try DeviceIdentityStore.save(identity)
            UserDefaults.standard.set(true, forKey: "deviceEnrolled")
        } catch {
            self.error = error.localizedDescription
        }
    }

    func unlock() async {
        isBusy = true
        defer { isBusy = false }
        do {
            let identity = try DeviceIdentityStore.read()
            let core = MobileVaultCore(vaultDirectory: vaultDirectory)
            // Touch the core to prove the identity is valid for this vault.
            _ = try core.publicKey(for: identity)
            self.core = core
            self.isUnlocked = true
            await loadEntries(identity: identity)
        } catch {
            self.error = error.localizedDescription
        }
    }

    func loadEntries(identity: String? = nil) async {
        guard let core = core else { return }
        isBusy = true
        defer { isBusy = false }
        do {
            let id: String
            if let identity {
                id = identity
            } else {
                id = try DeviceIdentityStore.read()
            }
            let paths = try core.listEntries(identity: id)
            // Read each entry header (read-only). Paths are the identity here.
            var result: [MobileVaultEntry] = []
            for path in paths {
                if let entry = try? core.readEntry(path: path, identity: id) {
                    result.append(entry)
                }
            }
            self.entries = result
        } catch {
            self.error = error.localizedDescription
        }
    }

    func copy(_ value: String) {
        UIPasteboard.general.string = value
    }
}
