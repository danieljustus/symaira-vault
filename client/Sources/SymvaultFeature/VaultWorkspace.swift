#if os(macOS)
  import SwiftUI
  import SymairaTheme
  import SymvaultKit

  /// The main window: the shared Symaira workspace with three destinations.
  /// While the vault is not ready, every destination shows the gate (connect,
  /// install, unlock or failure) instead of its content.
  public struct VaultWorkspace: View {
    @Bindable private var model: VaultAppModel
    @Environment(\.openSettings) private var openSettings
    @State private var sidebar = SymairaSidebarState()
    @State private var topography = SymairaTopoModel()

    public init(model: VaultAppModel) {
      self.model = model
    }

    private var store: VaultStore { model.store }

    public var body: some View {
      SymairaWorkspace(
        sidebar: $sidebar,
        // Topography sits behind the overview and the gate only (SHELL-8, MOTION-1).
        topography: showsTopography ? topography : nil,
        navigation: { showsLabels in sidebarContent(showsLabels: showsLabels) },
        content: { content }
      )
      .tint(SymairaTokens.selected)
      .toolbar {
        SymairaWorkspaceToolbar(sidebar: $sidebar) { openSettings() }
      }
      .task {
        if store.availability == .checking {
          await store.refresh()
        }
      }
      .onAppear { topography.state = topoState }
      .onChange(of: topoState) { _, state in topography.state = state }
      .onChange(of: store.selectedPath) { _, path in
        Task { await store.load(path: path) }
      }
      .onReceive(NotificationCenter.default.publisher(for: IntakeAppDelegate.openFilesNotification))
      {
        note in
        model.openImport(files: (note.object as? [URL]) ?? [])
      }
      .onChange(of: SelectionInbox.shared.pending, initial: true) { _, text in
        guard let text else { return }
        SelectionInbox.shared.pending = nil
        model.selectionIntake = SelectionIntakeItem(text: text)
      }
      .sheet(item: $model.editorContext) { context in
        EntryEditorView(context: context)
          .environment(store)
      }
      .sheet(item: Binding(get: { gatedSelection }, set: { model.selectionIntake = $0 })) { item in
        SelectionIntakeView(text: item.text)
          .environment(store)
      }
      .confirmationDialog(
        "Delete \(model.deleteCandidate ?? "Entry")?",
        isPresented: Binding(
          get: { model.deleteCandidate != nil },
          set: { if !$0 { model.deleteCandidate = nil } }
        ),
        titleVisibility: .visible,
        presenting: model.deleteCandidate
      ) { path in
        Button("Delete Entry", role: .destructive) {
          Task { _ = await store.delete(path: path) }
        }
        Button("Cancel", role: .cancel) {}
      } message: { _ in
        Text("The encrypted entry is removed from the vault and cannot be restored here.")
      }
    }

    /// The service sheet waits until the vault is unlocked, so the path check
    /// against existing entries and the save have a session.
    private var gatedSelection: SelectionIntakeItem? {
      model.canUseVault ? model.selectionIntake : nil
    }

    private var showsTopography: Bool {
      !model.canUseVault || model.destination == .overview
    }

    private var topoState: SymairaTopoState {
      switch store.availability {
      case .checking: .thinking
      case .missing, .failed: .problem
      case .locked: .input
      case .ready: store.isBusy ? .thinking : .idle
      }
    }

    // MARK: - Sidebar

    private func sidebarContent(showsLabels: Bool) -> some View {
      VStack(alignment: showsLabels ? .leading : .center, spacing: SymairaSpacing.large) {
        HStack(spacing: SymairaSpacing.small) {
          SymairaIconView(.productVault)
            .foregroundStyle(SymairaTokens.ink2)
            .frame(width: 32, height: 36)
            .accessibilityHidden(true)
          if showsLabels {
            Text("Symaira Vault")
              .symairaText(.heading)
              .lineLimit(1)
          }
        }
        .padding(.bottom, SymairaSpacing.small)

        VStack(spacing: SymairaSpacing.xSmall) {
          ForEach(VaultDestination.allCases) { item in
            SymairaNavigationButton(
              item.title, icon: item.icon,
              isSelected: model.destination == item, showsLabel: showsLabels
            ) {
              model.destination = item
            }
            .accessibilityIdentifier("vault-nav-\(item.id)")
          }
        }
        .padding(3)

        Spacer(minLength: 0)

        Divider().overlay(SymairaTokens.line)
        if showsLabels {
          SymairaStatusLabel(status.label, tone: status.tone)
            .padding(.horizontal, SymairaSpacing.small)
            .accessibilityIdentifier("vault-status")
        } else {
          SymairaStatusDot(tone: status.tone, accessibilityLabel: status.label)
            .help(status.label)
        }
      }
      .padding(SymairaSpacing.medium)
      .frame(maxHeight: .infinity)
    }

    private var status: (label: String, tone: SymairaTone) {
      switch store.availability {
      case .checking: ("Connecting…", .neutral)
      case .missing: ("symvault Not Found", .critical)
      case .locked: ("Locked", .warning)
      case .failed: ("Vault Unavailable", .critical)
      case .ready:
        (
          store.entries.count == 1
            ? "Unlocked · 1 entry" : "Unlocked · \(store.entries.count) entries", .positive
        )
      }
    }

    // MARK: - Content

    @ViewBuilder
    private var content: some View {
      Group {
        if model.canUseVault {
          switch model.destination {
          case .overview: OverviewPage(model: model)
          case .entries: EntriesPage(model: model)
          case .importing: ImportPage(model: model)
          }
        } else {
          GatePage(model: model)
        }
      }
      .environment(store)
      .accessibilityElement(children: .contain)
      .accessibilityIdentifier("vault-content-\(model.canUseVault ? model.destination.id : "gate")")
    }
  }
#endif
