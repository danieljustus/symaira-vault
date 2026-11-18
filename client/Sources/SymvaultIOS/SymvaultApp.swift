import SwiftUI
import SymairaTheme

@main
struct SymvaultIOSApp: App {
    @StateObject private var store = VaultStore()
    @StateObject private var approvalsStore = ApprovalsStore()

    var body: some Scene {
        WindowGroup {
            Group {
                if !store.isEnrolled {
                    EnrollView()
                } else if !store.isUnlocked {
                    UnlockView()
                } else {
                    MainTabView()
                }
            }
            .environmentObject(store)
            .environmentObject(approvalsStore)
            .tint(SymairaTokens.selected)
        }
    }
}

/// Signed-in shell: the vault and the approval device, native `TabView` (IOS-1).
struct MainTabView: View {
    enum Tab: Hashable { case vault, approvals }

    @EnvironmentObject private var approvalsStore: ApprovalsStore
    @State private var tab: Tab = .vault

    var body: some View {
        TabView(selection: $tab) {
            EntryListView()
                // The tab bar renders only Image, so the icon is a still (IOS-6).
                .tabItem { Label { Text(L("Vault")) } icon: { Image(symairaIcon: .productVault) } }
                .tag(Tab.vault)
            ApprovalsListView()
                .tabItem { Label { Text(L("Approvals")) } icon: { Image(symairaIcon: .shieldCheck) } }
                .badge(approvalsStore.pending.count)
                .tag(Tab.approvals)
        }
    }
}
