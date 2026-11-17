#if os(macOS)
  import AppKit
  import SwiftUI
  import SymairaTheme
  import SymvaultKit

  /// Screen card. Destination: Entries (2 of 3). Job: find an entry, copy or
  /// reveal its secret, and maintain entries; primary action New Entry (⌘N).
  /// Data: `symvault list` for the table, `symvault get` for the selected
  /// entry, loaded on unlock, selection and ⌘R; a TOTP refreshes when its code
  /// expires. States: gate covers connecting, missing, failed and locked;
  /// empty vault and no match show an empty state; load errors show a critical
  /// notice above the table. Density: sortable table plus a detail column.
  /// Platform: macOS workspace; no preference keys.
  struct EntriesPage: View {
    let model: VaultAppModel
    @Environment(VaultStore.self) private var store
    @State private var sortOrder = [KeyPathComparator(\VaultEntrySummary.path)]
    @FocusState private var searchFocused: Bool

    var body: some View {
      @Bindable var store = store

      SymairaPage(
        title: "Entries", subtitle: "Secrets stay masked until you reveal them",
        scrolls: false, maxWidth: 1180
      ) {
        TextField("Search by path, type or hint", text: $store.searchText)
          .textFieldStyle(.symaira(isFocused: searchFocused))
          .focused($searchFocused)
          .frame(maxWidth: 320)
          .accessibilityLabel("Search entries")
        Spacer()
        SymairaIconButton("Refresh", icon: .refresh, action: model.refresh)
          .disabled(store.isBusy)
        Button(action: model.newEntry) { Label("New Entry", symairaIcon: .add) }
          .symairaButtonStyle(.primary)
      } content: {
        VaultNotices()
        if store.filteredEntries.isEmpty {
          if store.searchText.isEmpty {
            SymairaPageEmpty(
              icon: .key, title: "No Entries",
              message: "The vault is empty. Use New Entry, or import credential files from Import."
            )
          } else {
            SymairaPageEmpty(
              icon: .search, title: "No Matching Entries",
              message: "Nothing matches “\(store.searchText)”. Try part of the path instead."
            ) {
              Button("Clear Search") { store.searchText = "" }
                .symairaButtonStyle(.secondary)
            }
          }
        } else {
          HStack(alignment: .top, spacing: SymairaSpacing.medium) {
            table
            detailColumn
              .frame(width: 360)
          }
          .frame(maxHeight: .infinity, alignment: .top)
        }
      }
      .background {
        // ⌘F focuses the search field (KEY-1).
        Button("Find") { searchFocused = true }
          .keyboardShortcut("f", modifiers: .command)
          .hidden()
      }
    }

    private var table: some View {
      @Bindable var store = store

      return Table(
        store.filteredEntries.sorted(using: sortOrder), selection: $store.selectedPath,
        sortOrder: $sortOrder
      ) {
        TableColumn("Entry", value: \.path) { entry in
          VStack(alignment: .leading, spacing: 2) {
            Text(verbatim: entry.title).symairaText(.bodyEmphasized)
            Text(verbatim: entry.path).symairaText(.monoSmall).foregroundStyle(SymairaTokens.ink3)
          }
          .padding(.vertical, 2)
        }
        .width(min: 200, ideal: 340)
        TableColumn("Type", value: \.typeLabel) { entry in
          Text(verbatim: entry.typeLabel).symairaText(.secondary)
        }
        .width(min: 70, ideal: 100, max: 160)
        TableColumn("Fields", value: \.fieldCountSortKey) { entry in
          Text(verbatim: entry.fieldCount.map(String.init) ?? "—")
            .symairaText(.secondary)
            .monospacedDigit()
            .frame(maxWidth: .infinity, alignment: .trailing)
        }
        .width(min: 50, ideal: 60, max: 80)
      }
      .contextMenu(forSelectionType: String.self) { paths in
        if let path = paths.first {
          Button("Copy Path") { copyPath(path) }
          Button("Edit Entry…") { edit(path: path) }
          Divider()
          Button("Delete Entry…", role: .destructive) { model.deleteCandidate = path }
        }
      }
      .onDeleteCommand(perform: model.requestDeleteSelected)
      .clipShape(RoundedRectangle(cornerRadius: SymairaRadius.card, style: .continuous))
      .accessibilityLabel("Entries")
    }

    @ViewBuilder
    private var detailColumn: some View {
      if let detail = store.detail, detail.path == store.selectedPath {
        EntryDetailView(
          detail: detail,
          onEdit: { edit(path: detail.path) },
          onDelete: { model.deleteCandidate = detail.path }
        )
      } else if store.selectedPath != nil {
        SymairaLoadingState("Decrypting entry…")
          .frame(maxWidth: .infinity, minHeight: SymairaPageLayout.stateHeight)
          .symairaCard()
      } else {
        SymairaEmptyState(
          icon: .sidebar, title: "No Entry Selected",
          message: "Select an entry to see its fields. Secrets stay masked until you reveal them."
        )
        .frame(maxWidth: .infinity)
        .symairaCard()
      }
    }

    /// The editor needs the decrypted values, so an entry opened from the
    /// context menu is selected and loaded first.
    private func edit(path: String) {
      Task {
        if store.detail?.path != path {
          store.selectedPath = path
          await store.load(path: path)
        }
        guard let detail = store.detail, detail.path == path else { return }
        model.editorContext = EntryEditorContext(
          detail: detail, summary: store.entries.first { $0.path == path })
      }
    }

    private func copyPath(_ path: String) {
      let pasteboard = NSPasteboard.general
      pasteboard.clearContents()
      pasteboard.setString(path, forType: .string)
    }
  }

  extension VaultEntrySummary {
    var typeLabel: String {
      guard let type, !type.isEmpty else { return "" }
      return type.replacingOccurrences(of: "_", with: " ")
    }

    var fieldCountSortKey: Int { fieldCount ?? -1 }
  }
#endif
