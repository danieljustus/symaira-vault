import SwiftUI
import SymairaTheme

/// First-launch enrolment. Generates a device identity and stores it in the
/// Keychain bound to Face ID (ThisDeviceOnly). The master identity never leaves
/// the device; only its public key is shared with the vault host.
struct EnrollView: View {
    @EnvironmentObject private var store: VaultStore
    @State private var topography = SymairaTopoModel()

    var body: some View {
        NavigationStack {
            SymairaPage(title: L("Symaira Vault"), subtitle: L("Your vault, read-only on this iPhone")) {
                VStack(alignment: .leading, spacing: SymairaSpacing.large) {
                    SymairaFormSection(
                        L("Enrol This iPhone"),
                        footer: L(
                            "The device identity stays on this iPhone, protected by Face ID. Only its public key is shared with your Mac."
                        )
                    ) {
                        SymairaFormRow(
                            L("Read-Only"), description: L("Browse entries and copy values. Changes stay on your Mac."))
                        SymairaFormDivider()
                        SymairaFormRow(
                            L("Approval Device"), description: L("Approve or deny agent requests with Face ID."))
                    }
                    Button {
                        Task { await store.enroll() }
                    } label: {
                        Text(store.isBusy ? L("Enrolling…") : L("Enrol This iPhone"))
                            .frame(maxWidth: .infinity)
                    }
                    .symairaButtonStyle(.primary)
                    .disabled(store.isBusy)
                    if let error = store.error {
                        SymairaNotice(message: error, tone: .critical) { store.error = nil }
                    }
                }
            }
            .symairaTopography(topography)
            .toolbar(.hidden, for: .navigationBar)
        }
        .onAppear { topography.state = .input }
    }
}
