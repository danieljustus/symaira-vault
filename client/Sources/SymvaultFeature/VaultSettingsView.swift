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
          SymairaFormSection(L("Appearance")) {
            SymairaFormRow(L("Color Scheme")) {
              SymairaAppearancePicker(selection: $appearance)
                .frame(width: 300)
            }
          }

          SymairaFormSection(
            L("Runtime"),
            footer:
              L("The app uses the symvault bundled with it, then PATH and the Homebrew prefixes.")
          ) {
            SymairaFormRow(L("Status")) {
              SymairaStatusLabel(statusLabel.text, tone: statusLabel.tone)
            }
            if let runtime = store.runtime {
              SymairaFormDivider()
              SymairaFormRow(L("Version")) { value(runtime.version ?? L("Unknown")) }
              SymairaFormDivider()
              SymairaFormRow(L("Source")) { value(runtime.source) }
              SymairaFormDivider()
              SymairaFormRow(L("Path")) { value(runtime.path) }
              SymairaFormDivider()
              SymairaFormRow(L("JSON Schema")) {
                value(runtime.schemaVersion.map(String.init) ?? L("Unknown"))
              }
            }
            HStack {
              Spacer()
              Button(L("Check Runtime"), action: model.refresh)
                .symairaButtonStyle(.secondary)
                .disabled(store.isBusy)
            }
            .padding(.bottom, SymairaSpacing.small)
          }

          SymairaFormSection(
            L("About"),
            footer:
              L(
                "Symaira Vault is the native client for the self-hosted symvault runtime. Copied secrets leave the clipboard after 30 seconds."
              )
          ) {
            SymairaFormRow(L("App")) { value(appVersion) }
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
      case .checking: (L("Connecting…"), .neutral)
      case .missing: (L("Not Found"), .critical)
      case .locked: (L("Locked"), .warning)
      case .ready: (L("Unlocked"), .positive)
      case .failed: (L("Unavailable"), .critical)
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
