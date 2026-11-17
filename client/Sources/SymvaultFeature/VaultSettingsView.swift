#if os(macOS)
  import SwiftUI
  import SymairaTheme
  import SymvaultKit

  /// The native Settings window (⌘,): appearance, runtime, about.
  public struct VaultSettingsView: View {
    private let model: VaultAppModel
    @AppStorage(VaultPreferenceKey.appearance) private var appearance: SymairaAppearance = .system

    public init(model: VaultAppModel) {
      self.model = model
    }

    private var store: VaultStore { model.store }

    public var body: some View {
      ScrollView {
        VStack(alignment: .leading, spacing: SymairaSpacing.large) {
          SymairaFormSection("Appearance") {
            SymairaFormRow("Color Scheme") {
              SymairaAppearancePicker(selection: $appearance)
                .frame(width: 300)
            }
          }

          SymairaFormSection(
            "Runtime",
            footer:
              "The app uses the symvault bundled with it, then PATH and the Homebrew prefixes."
          ) {
            SymairaFormRow("Status") {
              SymairaStatusLabel(statusLabel.text, tone: statusLabel.tone)
            }
            if let runtime = store.runtime {
              SymairaFormDivider()
              SymairaFormRow("Version") { value(runtime.version ?? "Unknown") }
              SymairaFormDivider()
              SymairaFormRow("Source") { value(runtime.source) }
              SymairaFormDivider()
              SymairaFormRow("Path") { value(runtime.path) }
              SymairaFormDivider()
              SymairaFormRow("JSON Schema") {
                value(runtime.schemaVersion.map(String.init) ?? "Unknown")
              }
            }
            HStack {
              Spacer()
              Button("Check Runtime", action: model.refresh)
                .symairaButtonStyle(.secondary)
                .disabled(store.isBusy)
            }
            .padding(.bottom, SymairaSpacing.small)
          }

          SymairaFormSection(
            "About",
            footer:
              "Symaira Vault is the native client for the self-hosted symvault runtime. Copied secrets leave the clipboard after 30 seconds."
          ) {
            SymairaFormRow("App") { value(appVersion) }
          }
        }
        .padding(SymairaSpacing.xLarge)
      }
      .background(SymairaTokens.canvas)
      .onAppear { appearance.apply() }
      .onChange(of: appearance) { _, value in value.apply() }
    }

    private func value(_ text: String) -> some View {
      Text(verbatim: text)
        .symairaText(.monoSmall)
        .foregroundStyle(SymairaTokens.ink)
        .textSelection(.enabled)
        .lineLimit(1)
        .truncationMode(.middle)
        .frame(maxWidth: 320, alignment: .trailing)
        .help(text)
    }

    private var statusLabel: (text: String, tone: SymairaTone) {
      switch store.availability {
      case .checking: ("Connecting…", .neutral)
      case .missing: ("Not Found", .critical)
      case .locked: ("Locked", .warning)
      case .ready: ("Unlocked", .positive)
      case .failed: ("Unavailable", .critical)
      }
    }

    private var appVersion: String {
      let info = Bundle.main.infoDictionary
      let version = info?["CFBundleShortVersionString"] as? String ?? "0.0"
      let build = info?["CFBundleVersion"] as? String ?? "0"
      return "\(version) (\(build))"
    }
  }
#endif
