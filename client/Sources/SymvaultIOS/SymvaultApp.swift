import SwiftUI

@main
struct SymvaultIOSApp: App {
    @StateObject private var store = VaultStore()

    var body: some Scene {
        WindowGroup {
            Group {
                if !store.isEnrolled {
                    EnrollView()
                } else if !store.isUnlocked {
                    UnlockView()
                } else {
                    EntryListView()
                }
            }
            .environmentObject(store)
            .alert("Error", isPresented: Binding(
                get: { store.error != nil },
                set: { if !$0 { store.error = nil } }
            )) {
                Button("OK", role: .cancel) {}
            } message: {
                Text(store.error ?? "")
            }
        }
    }
}
