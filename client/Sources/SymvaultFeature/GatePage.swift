#if os(macOS)
  import SwiftUI
  import SymairaTheme
  import SymvaultKit

  /// Shown in place of every destination until the vault is ready.
  ///
  /// Screen card. Destination: any (gate in front of all three). Job: unlock
  /// the vault; primary action Unlock Vault. Data: `symvault` discovery,
  /// `status` and `unlock` over the bundled or installed CLI, checked on launch
  /// and ⌘R. States: connecting, symvault not installed, schema or runtime
  /// failure with Retry, locked. Density: prose column. Platform: macOS
  /// workspace; no preference keys (the profile is per session, as before).
  struct GatePage: View {
    let model: VaultAppModel
    @Environment(VaultStore.self) private var store

    var body: some View {
      switch store.availability {
      case .checking, .ready:
        SymairaPage(
          title: L("Symaira Vault"), subtitle: L("Connecting to the local symvault runtime")
        ) {
          SymairaPageState(
            state: SymairaPageLoadState<Void>.loading, loading: L("Connecting to the vault…"),
            retry: model.refresh
          ) { _ in EmptyView() }
        }
      case .missing:
        MissingRuntimePage(model: model)
      case .failed(let message):
        SymairaPage(
          title: L("Vault Unavailable"), subtitle: L("symvault answered, but the app cannot use it")
        ) {
          SymairaPageState(
            state: SymairaPageLoadState<Void>.failed(message), loading: "", retry: model.refresh
          ) { _ in EmptyView() }
        }
      case .locked:
        UnlockPage()
      }
    }
  }

  private struct MissingRuntimePage: View {
    let model: VaultAppModel
    @Environment(VaultStore.self) private var store
    private let command = "brew install danieljustus/tap/symvault"

    var body: some View {
      SymairaPage(
        title: L("Install symvault"),
        subtitle: L("The app manages the vault through the symvault runtime")
      ) {
        SymairaPageEmpty(
          icon: .productVault,
          title: L("symvault Not Found"),
          message:
            L(
              "The app found no symvault in its bundle, on PATH or in Homebrew. Install it, then check again."
            )
        ) {
          VStack(spacing: SymairaSpacing.medium) {
            HStack(spacing: SymairaSpacing.small) {
              Text(verbatim: command)
                .symairaText(.mono)
                .foregroundStyle(SymairaTokens.ink)
                .textSelection(.enabled)
              SymairaIconButton(L("Copy Install Command"), icon: .copy, size: 16) {
                store.copy(command, label: L("Install command"))
              }
            }
            .symairaCard(padding: SymairaSpacing.medium)
            Button(action: model.refresh) { Label(L("Check Again"), symairaIcon: .refresh) }
              .symairaButtonStyle(.primary)
          }
        }
        VaultNotices()
      }
    }
  }

  private struct UnlockPage: View {
    @Environment(VaultStore.self) private var store
    @State private var passphrase = ""
    @State private var ttl = "15m"
    @FocusState private var passphraseFocused: Bool

    var body: some View {
      @Bindable var store = store

      SymairaPage(
        title: L("Unlock Vault"),
        subtitle: L("Your entries stay encrypted until you unlock the vault")
      ) {
        VStack(alignment: .leading, spacing: SymairaSpacing.medium) {
          SymairaFormSection(
            L("Session"),
            footer: L(
              "The passphrase goes to symvault over standard input. The app never stores it.")
          ) {
            SymairaFormRow(L("Passphrase")) {
              SecureField(L("Vault passphrase"), text: $passphrase)
                .textFieldStyle(.symaira(isFocused: passphraseFocused))
                .focused($passphraseFocused)
                .frame(width: 260)
                .accessibilityLabel(L("Vault passphrase"))
                .onSubmit(unlock)
            }
            SymairaFormDivider()
            SymairaFormRow(L("Stay Unlocked For")) {
              SymairaSegmentedControl(
                L("Session length"), selection: $ttl,
                options: [
                  (value: "15m", label: L("15 min")), (value: "1h", label: L("1 hour")),
                  (value: "8h", label: L("8 hours")),
                ]
              )
            }
            SymairaFormDivider()
            SymairaFormRow(
              L("Profile"), description: L("Leave empty for the default vault profile.")
            ) {
              TextField(L("Default"), text: $store.profile)
                .textFieldStyle(.symaira)
                .frame(width: 260)
                .accessibilityLabel(L("Vault profile"))
            }
          }

          HStack(spacing: SymairaSpacing.medium) {
            Button(action: unlock) {
              Label(store.isBusy ? L("Unlocking…") : L("Unlock Vault"), symairaIcon: .unlock)
                .frame(minWidth: 140)
            }
            .symairaButtonStyle(.primary)
            .keyboardShortcut(.defaultAction)
            .disabled(passphrase.isEmpty || store.isBusy)
            if passphrase.isEmpty {
              Text(L("Enter the passphrase to unlock.")).symairaText(.caption)
            }
          }

          if let message = store.errorMessage {
            SymairaNotice(title: L("Vault Still Locked"), message: message, tone: .critical) {
              store.clearError()
            }
          }

          if let runtime = store.runtime {
            Text(verbatim: "\(runtime.version ?? "symvault") · \(runtime.source)")
              .symairaText(.caption)
              .help(runtime.path)
          }
        }
      }
      .onAppear { passphraseFocused = true }
    }

    private func unlock() {
      guard !passphrase.isEmpty, !store.isBusy else { return }
      let submitted = passphrase
      passphrase = ""
      Task { _ = await store.unlock(passphrase: submitted, ttl: ttl) }
    }
  }

  /// Inline feedback shared by every page: errors (critical, dismissible) and
  /// the clipboard confirmation (positive). No modal alerts (ACTION-8).
  struct VaultNotices: View {
    @Environment(VaultStore.self) private var store

    var body: some View {
      VStack(alignment: .leading, spacing: SymairaSpacing.small) {
        if let message = store.errorMessage {
          SymairaNotice(message: message, tone: .critical) { store.clearError() }
        }
        if let notice = store.clipboardNotice {
          SymairaNotice(message: notice, tone: .positive)
        }
      }
      .animation(.default, value: store.errorMessage)
      .animation(.default, value: store.clipboardNotice)
    }
  }
#endif
