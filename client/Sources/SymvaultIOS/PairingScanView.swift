import SwiftUI
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
        NavigationStack {
            Form {
                Section {
                    TextField("Device name", text: $deviceName)
                } header: {
                    Text("This device")
                }

                Section {
                    if DataScannerViewController.isSupported && DataScannerViewController.isAvailable {
                        Button {
                            showScanner = true
                        } label: {
                            Label("Scan QR Code", systemImage: "qrcode.viewfinder")
                        }
                    } else {
                        Text("Camera scanning is not available on this device.")
                            .foregroundStyle(.secondary)
                    }
                } header: {
                    Text("Scan")
                }

                Section {
                    TextEditor(text: $manualPayload)
                        .frame(minHeight: 100)
                        .font(.system(.body, design: .monospaced))
                    Button("Pair") {
                        Task { await pairManually() }
                    }
                    .disabled(manualPayload.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || approvalsStore.isBusy)
                } header: {
                    Text("Or enter manually")
                } footer: {
                    Text("Paste the text shown below the QR code on your Mac.")
                }

                if let error = approvalsStore.error {
                    Section {
                        Text(error).foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("Pair Approval Device")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
            .overlay {
                if approvalsStore.isBusy {
                    ProgressView()
                }
            }
            .sheet(isPresented: $showScanner) {
                QRScannerRepresentable { scanned in
                    showScanner = false
                    Task { await pair(scanned) }
                }
            }
        }
    }

    private func pairManually() async {
        await pair(manualPayload)
    }

    private func pair(_ raw: String) async {
        guard let data = raw.trimmingCharacters(in: .whitespacesAndNewlines).data(using: .utf8),
              let payload = try? JSONDecoder().decode(ApprovalPairingPayload.self, from: data)
        else {
            approvalsStore.error = "Could not read the pairing code. Copy the exact text shown by 'symvault device approval-pair'."
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
