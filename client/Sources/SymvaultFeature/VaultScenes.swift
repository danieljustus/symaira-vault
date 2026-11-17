#if os(macOS)
  import SwiftUI
  import SymairaTheme

  /// The app's scenes: the workspace window with its menu commands and the
  /// native Settings window. Lives here so the app target needs no theme import.
  public struct VaultScenes: Scene {
    @Bindable private var model: VaultAppModel
    @AppStorage(VaultPreferenceKey.appearance) private var appearance: SymairaAppearance = .system

    public init(model: VaultAppModel) {
      self.model = model
    }

    public var body: some Scene {
      WindowGroup(L("Symaira Vault")) {
        VaultWorkspace(model: model)
          // Sidebar 272 pt plus the table and detail column (SHELL-4).
          .frame(minWidth: 960, minHeight: 620)
          .onAppear { appearance.apply() }
          .onChange(of: appearance) { _, value in value.apply() }
      }
      .symairaWorkspaceWindow()
      .windowResizability(.contentMinSize)
      .defaultSize(width: 1180, height: 780)
      .commands {
        SymairaCommands(
          destinations: VaultDestination.commandEntries, selection: $model.destination)
        // WindowGroup owns ⌘N for a new window; New Entry replaces it.
        CommandGroup(replacing: .newItem) {
          Button(L("New Entry"), action: model.newEntry)
            .keyboardShortcut("n", modifiers: .command)
            .disabled(!model.canUseVault)
          Button(L("Import Files…")) { model.openImport() }
            .keyboardShortcut("i", modifiers: [.command, .shift])
        }
        CommandMenu(L("Vault")) {
          Button(L("Refresh"), action: model.refresh)
            .keyboardShortcut("r", modifiers: .command)
          Divider()
          Button(L("Delete Entry…"), action: model.requestDeleteSelected)
            .disabled(!model.canUseVault || model.store.selectedPath == nil)
          Divider()
          Button(L("Lock Vault"), action: model.lock)
            .keyboardShortcut("l", modifiers: [.command, .shift])
            .disabled(!model.canUseVault)
        }
      }

      SymairaSettingsScene {
        VaultSettingsView(model: model)
          .frame(width: 600)
          .frame(minHeight: 660)
      }
    }
  }
#endif
