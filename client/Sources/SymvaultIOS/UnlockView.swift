import SwiftUI

/// Unlock prompt. On iOS the passphrase is entered once at enrolment and
/// thereafter replaced by Face ID: reading the Keychain identity triggers the
/// local biometric prompt. This view is shown only as a fallback / first open
/// before the biometric path is established.
struct UnlockView: View {
    @EnvironmentObject private var store: VaultStore

    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "faceid")
                .font(.system(size: 44, weight: .light))
                .foregroundStyle(.tint)
            Text("Unlock with Face ID")
                .font(.title2.weight(.semibold))
            Text("Symaira Vault uses Face ID to read your device identity.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 340)
            Button {
                Task { await store.unlock() }
            } label: {
                if store.isBusy {
                    ProgressView().controlSize(.small)
                } else {
                    Text("Unlock")
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(store.isBusy)
        }
        .padding(40)
        .task { await store.unlock() }
    }
}
