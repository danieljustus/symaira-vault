import SwiftUI
import SymairaTheme

/// Unlock prompt. Reading the Keychain identity triggers the Face ID prompt;
/// the view starts that on appear and keeps a button for a retry.
struct UnlockView: View {
    @EnvironmentObject private var store: VaultStore
    @State private var topography = SymairaTopoModel()

    var body: some View {
        NavigationStack {
            SymairaPage(title: L("Unlock Vault"), subtitle: L("Face ID reads your device identity")) {
                VStack(alignment: .leading, spacing: SymairaSpacing.large) {
                    if store.isBusy {
                        SymairaLoadingState(L("Unlocking…"))
                            .frame(maxWidth: .infinity, minHeight: SymairaPageLayout.stateHeight)
                    } else {
                        SymairaEmptyState(
                            icon: .faceId,
                            title: L("Vault Locked"),
                            message: L("Unlock with Face ID to see your entries.")
                        ) {
                            Button {
                                Task { await store.unlock() }
                            } label: {
                                Label(L("Unlock with Face ID"), symairaIcon: .faceId)
                            }
                            .symairaButtonStyle(.primary)
                        }
                        .frame(maxWidth: .infinity)
                    }
                    if let error = store.error {
                        SymairaNotice(title: L("Vault Still Locked"), message: error, tone: .critical) {
                            store.error = nil
                        }
                    }
                }
            }
            .symairaTopography(topography)
            .toolbar(.hidden, for: .navigationBar)
        }
        .onAppear { topography.state = .input }
        .task { await store.unlock() }
    }
}
