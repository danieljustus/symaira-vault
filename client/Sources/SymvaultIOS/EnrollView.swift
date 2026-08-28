import SwiftUI

/// First-launch enrolment. Generates a device identity and stores it in the
/// Keychain bound to Face ID (ThisDeviceOnly). The master identity never leaves
/// the device; only its public key is shared with the vault host.
struct EnrollView: View {
    @EnvironmentObject private var store: VaultStore
    @State private var enrolling = false

    var body: some View {
        VStack(spacing: 24) {
            Image(systemName: "lock.shield.fill")
                .font(.system(size: 48, weight: .light))
                .foregroundStyle(.tint)
            Text("Symaira Vault")
                .font(.largeTitle.weight(.semibold))
            Text("Enrol this device as a read-only vault companion. Your device identity is stored on this device only and protected by Face ID.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 360)
            Button {
                Task { await store.enroll() }
            } label: {
                if enrolling || store.isBusy {
                    ProgressView().controlSize(.small)
                } else {
                    Text("Enrol this device")
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(enrolling || store.isBusy)
            if let error = store.error {
                Text(error)
                    .font(.callout)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 360)
            }
        }
        .padding(40)
        .onChange(of: store.isEnrolled) { _, _ in enrolling = false }
        .onAppear { enrolling = store.isBusy }
    }
}
