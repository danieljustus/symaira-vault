import SwiftUI
import SymairaTheme
import UIKit
import VisionKit

/// Pairing entry point: scan the QR code shown by
/// `symvault device approval-pair`, or paste/type its JSON payload manually.
/// Manual entry exists both as an accessibility fallback and because QR
/// scanning needs a real camera — it never works in the iOS Simulator.
struct PairingScanView: View {
    @EnvironmentObject private var approvalsStore: ApprovalsStore
    @Environment(\.dismiss) private var dismiss

    @State private var manualPayload: String = ""
    @State private var deviceName: String = UIDevice.current.name
    @State private var showScanner = false

    var body: some View {
        SymairaSheetScaffold(
            title: L("Pair Approval Device"),
            dismiss: { dismiss() },
            primaryTitle: approvalsStore.isBusy ? L("Pairing…") : L("Pair Device"),
            primaryDisabled: manualPayload.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                || approvalsStore.isBusy,
            primary: { Task { await pair(manualPayload) } }
        ) {
            SymairaFormSection(L("This Device")) {
                SymairaFormRow(L("Device Name")) {
                    TextField(L("iPhone"), text: $deviceName)
                        .textFieldStyle(.symaira)
                        .multilineTextAlignment(.trailing)
                        .accessibilityLabel(L("Device Name"))
                }
            }

            SymairaFormSection(L("Scan"), footer: L("On your Mac, start 'symvault serve --bind <Mac IP address>', then run 'symvault device approval-pair' and scan the QR code it shows. iPhone and Mac must be on the same network.")) {
                if DataScannerViewController.isSupported && DataScannerViewController.isAvailable {
                    Button {
                        showScanner = true
                    } label: {
                        Label(L("Scan QR Code"), symairaIcon: .scan)
                            .frame(maxWidth: .infinity)
                    }
                    .symairaButtonStyle(.secondary)
                    .padding(.vertical, SymairaSpacing.small)
                } else {
                    Text(L("Camera scanning is not available on this device."))
                        .symairaText(.secondary)
                        .padding(.vertical, SymairaSpacing.small)
                }
            }

            SymairaFormSection(L("Or Enter Manually"), footer: L("Paste the text shown below the QR code on your Mac.")) {
                TextField(L("Pairing code"), text: $manualPayload, axis: .vertical)
                    .lineLimit(3...6)
                    .textFieldStyle(.symaira)
                    .font(SymairaTypography.monoSmall)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .accessibilityLabel(L("Pairing code"))
                    .padding(.vertical, SymairaSpacing.small)
            }

            if let error = approvalsStore.error {
                SymairaNotice(message: error, tone: .critical) { approvalsStore.error = nil }
            }
        }
        .sheet(isPresented: $showScanner) {
            QRScannerRepresentable { scanned in
                showScanner = false
                Task { await pair(scanned) }
            }
        }
    }

    private func pair(_ raw: String) async {
        guard let data = raw.trimmingCharacters(in: .whitespacesAndNewlines).data(using: .utf8),
              let payload = try? JSONDecoder().decode(ApprovalPairingPayload.self, from: data)
        else {
            approvalsStore.error = L("Could not read the pairing code. Copy the exact text shown by 'symvault device approval-pair'.")
            return
        }
        await approvalsStore.pair(with: payload, deviceName: deviceName)
        if approvalsStore.error == nil {
            dismiss()
        }
    }
}

/// Wraps VisionKit's DataScannerViewController to recognize a QR code and
/// hand its raw payload string back to SwiftUI.
private struct QRScannerRepresentable: UIViewControllerRepresentable {
    let onScan: (String) -> Void

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let controller = DataScannerViewController(
            recognizedDataTypes: [.barcode(symbologies: [.qr])],
            qualityLevel: .balanced,
            isHighlightingEnabled: true
        )
        controller.delegate = context.coordinator
        try? controller.startScanning()
        return controller
    }

    func updateUIViewController(_ uiViewController: DataScannerViewController, context: Context) {}

    func makeCoordinator() -> Coordinator {
        Coordinator(onScan: onScan)
    }

    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        private let onScan: (String) -> Void
        private var handled = false

        init(onScan: @escaping (String) -> Void) {
            self.onScan = onScan
        }

        func dataScanner(_ dataScanner: DataScannerViewController, didAdd addedItems: [RecognizedItem], allItems: [RecognizedItem]) {
            guard !handled else { return }
            for item in addedItems {
                if case let .barcode(barcode) = item, let payload = barcode.payloadStringValue {
                    handled = true
                    onScan(payload)
                    return
                }
            }
        }
    }
}
