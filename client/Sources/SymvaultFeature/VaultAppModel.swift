#if os(macOS)
  import Observation
  import SwiftUI
  import SymairaTheme
  import SymvaultKit

  /// The three top-level destinations of the workspace sidebar, in menu order.
  /// Settings is deliberately absent: it lives in the native Settings window (⌘,).
  public enum VaultDestination: String, CaseIterable, Identifiable, Hashable, Sendable {
    case overview
    case entries
    case importing

    public var id: String { rawValue }

    public var title: String {
      switch self {
      case .overview: "Overview"
      case .entries: "Entries"
      case .importing: "Import"
      }
    }

    var icon: SymairaIcon {
      switch self {
      case .overview: .dashboard
      case .entries: .key
      case .importing: .inbox
      }
    }

    /// Ordered entries for `SymairaCommands` (⌘1 to ⌘3).
    public static var commandEntries: [(value: VaultDestination, label: String)] {
      allCases.map { (value: $0, label: $0.title) }
    }
  }

  /// Existing and new preference keys of the macOS app. The app had no stored
  /// preferences before the CoreKit workspace; it was dark-only.
  public enum VaultPreferenceKey {
    public static let appearance = "symvault.appearance"
  }

  /// App-owned state shared by the main window, the menu commands and the
  /// Settings window. One main window, so one selection (SHELL-9).
  @MainActor
  @Observable
  public final class VaultAppModel {
    public var destination: VaultDestination = .overview
    public let store: VaultStore
    public let intake: IntakeStore
    /// Set by the New Entry command; the workspace presents the editor.
    var editorContext: EntryEditorContext?
    var deleteCandidate: String?
    /// Text from the macOS service, shown once the vault is unlocked.
    var selectionIntake: SelectionIntakeItem?

    public init(client: VaultClient = VaultClient()) {
      store = VaultStore(client: client)
      intake = IntakeStore(client: client)
    }

    public var canUseVault: Bool { store.availability == .ready }

    public func newEntry() {
      guard canUseVault else { return }
      destination = .entries
      editorContext = .create
    }

    public func openImport(files: [URL] = []) {
      destination = .importing
      guard !files.isEmpty else { return }
      intake.addFiles(files)
      Task { await intake.runPreview() }
    }

    public func refresh() {
      Task { await store.refresh() }
    }

    public func lock() {
      Task { await store.lock() }
    }

    public func requestDeleteSelected() {
      guard canUseVault, let path = store.selectedPath else { return }
      deleteCandidate = path
    }
  }

  extension View {
    /// `SymairaFormRow` aligns trailing content on the first text baseline, so a
    /// control without text (switch) sits too high; center it on the label line.
    func centeredOnFormLabel() -> some View {
      alignmentGuide(.firstTextBaseline) { $0[VerticalAlignment.center] + 4 }
    }
  }

  struct EntryEditorContext: Identifiable {
    let id = UUID()
    let detail: VaultEntryDetail?
    let summary: VaultEntrySummary?

    static var create: EntryEditorContext {
      EntryEditorContext(detail: nil, summary: nil)
    }
  }
#endif
