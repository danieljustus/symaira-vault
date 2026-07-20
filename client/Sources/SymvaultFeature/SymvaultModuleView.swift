#if os(macOS)
  import SwiftUI
  import SymairaTheme
  import SymvaultKit

  public enum SymvaultModule {
    public static let expectedSchemaVersion = VaultClient.expectedSchemaVersion
  }

  public struct SymvaultModuleView: View {
    @State private var store: VaultStore

    @MainActor
    public init(client: VaultClient = VaultClient()) {
      _store = State(initialValue: VaultStore(client: client))
    }

    public var body: some View {
      SymvaultRootView()
        .environment(store)
        .preferredColorScheme(.dark)
        .task {
          if store.availability == .checking {
            await store.refresh()
          }
        }
    }
  }

  private struct SymvaultRootView: View {
    @Environment(VaultStore.self) private var store

    var body: some View {
      ZStack {
        SymairaTheme.bgDark.ignoresSafeArea()
        AmbientGlows().allowsHitTesting(false)
        BlueprintGrid().allowsHitTesting(false)

        switch store.availability {
        case .checking:
          ProgressView("Vault wird verbunden …")
            .tint(SymairaTheme.goldPrimary)
            .foregroundStyle(SymairaTheme.textSecondary)
        case .missing:
          RuntimeMissingView()
        case .locked:
          UnlockView()
        case .ready:
          VaultWorkspaceView()
        case .failed(let message):
          RuntimeFailureView(message: message)
        }
      }
      .overlay(alignment: .bottom) {
        if let notice = store.clipboardNotice {
          Label(notice, systemImage: "clipboard.fill")
            .font(.caption.weight(.medium))
            .foregroundStyle(SymairaTheme.textPrimary)
            .padding(.horizontal, 14)
            .padding(.vertical, 9)
            .glassmorphicPanel(cornerRadius: 9, addCorners: false)
            .padding(.bottom, 18)
            .transition(.move(edge: .bottom).combined(with: .opacity))
        }
      }
      .animation(SymairaTheme.transitionFast, value: store.clipboardNotice)
      .alert(
        "Symaira Vault",
        isPresented: Binding(
          get: { store.errorMessage != nil },
          set: { if !$0 { store.clearError() } }
        )
      ) {
        Button("OK", role: .cancel) { store.clearError() }
      } message: {
        Text(store.errorMessage ?? "Unbekannter Fehler")
      }
    }
  }

  private struct RuntimeMissingView: View {
    @Environment(VaultStore.self) private var store

    var body: some View {
      VStack(spacing: 18) {
        Image(systemName: "lock.square.stack")
          .font(.system(size: 48, weight: .light))
          .foregroundStyle(SymairaTheme.goldPrimary)
        Text("symvault fehlt")
          .font(.largeTitle.weight(.semibold))
          .foregroundStyle(SymairaTheme.textPrimary)
        Text("Installiere die öffentliche Runtime. Danach verbindet sich die App automatisch.")
          .foregroundStyle(SymairaTheme.textSecondary)
          .multilineTextAlignment(.center)
        HStack(spacing: 10) {
          Text("brew install danieljustus/tap/symvault")
            .font(.callout.monospaced())
            .foregroundStyle(SymairaTheme.goldPrimary)
            .textSelection(.enabled)
          Button {
            store.copy("brew install danieljustus/tap/symvault", label: "Installationsbefehl")
          } label: {
            Image(systemName: "doc.on.doc")
          }
          .buttonStyle(.plain)
          .help("Befehl kopieren")
        }
        .padding(14)
        .glassmorphicPanel(cornerRadius: 10, addCorners: false)

        Button("Erneut prüfen") { Task { await store.refresh() } }
          .buttonStyle(SymairaPrimaryButtonStyle())
      }
      .padding(36)
      .frame(maxWidth: 540)
    }
  }

  private struct RuntimeFailureView: View {
    let message: String
    @Environment(VaultStore.self) private var store

    var body: some View {
      VStack(spacing: 16) {
        Image(systemName: "exclamationmark.shield")
          .font(.system(size: 44, weight: .light))
          .foregroundStyle(.orange)
        Text("Vault nicht verfügbar")
          .font(.title.weight(.semibold))
          .foregroundStyle(SymairaTheme.textPrimary)
        Text(message)
          .foregroundStyle(SymairaTheme.textSecondary)
          .multilineTextAlignment(.center)
          .textSelection(.enabled)
        Button("Erneut versuchen") { Task { await store.refresh() } }
          .buttonStyle(SymairaPrimaryButtonStyle())
      }
      .padding(32)
      .frame(maxWidth: 520)
      .glassmorphicPanel()
    }
  }
#endif
