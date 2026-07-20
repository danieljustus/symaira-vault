#if os(macOS)
  import SwiftUI
  import SymairaTheme
  import SymvaultKit

  struct EntryEditorContext: Identifiable {
    let id = UUID()
    let detail: VaultEntryDetail?
    let summary: VaultEntrySummary?

    static var create: EntryEditorContext {
      EntryEditorContext(detail: nil, summary: nil)
    }
  }

  struct VaultWorkspaceView: View {
    @Environment(VaultStore.self) private var store
    @State private var editorContext: EntryEditorContext?
    @State private var showDeleteConfirmation = false

    var body: some View {
      @Bindable var store = store

      NavigationSplitView {
        List(selection: $store.selectedPath) {
          ForEach(store.groupedEntries, id: \.0) { group, entries in
            Section(group) {
              ForEach(entries) { entry in
                EntrySidebarRow(entry: entry)
                  .tag(entry.path)
              }
            }
          }
        }
        .listStyle(.sidebar)
        .scrollContentBackground(.hidden)
        .background(SymairaTheme.bgDarker.opacity(0.86))
        .navigationSplitViewColumnWidth(min: 230, ideal: 270, max: 340)
        .searchable(text: $store.searchText, placement: .sidebar, prompt: "Secrets durchsuchen")
        .overlay {
          if store.filteredEntries.isEmpty {
            ContentUnavailableView(
              store.searchText.isEmpty ? "Noch keine Secrets" : "Keine Treffer",
              systemImage: store.searchText.isEmpty ? "lock.square.stack" : "magnifyingglass",
              description: Text(
                store.searchText.isEmpty ? "Lege dein erstes Secret an." : "Ändere den Suchbegriff."
              )
            )
            .foregroundStyle(SymairaTheme.textSecondary)
          }
        }
        .safeAreaInset(edge: .bottom) {
          RuntimeFooter()
        }
      } detail: {
        ZStack {
          SymairaTheme.bgDark.ignoresSafeArea()
          AmbientGlows().allowsHitTesting(false)

          if store.isDetailLoading, store.detail == nil {
            ProgressView("Secret wird entschlüsselt …")
              .tint(SymairaTheme.goldPrimary)
          } else if let detail = store.detail {
            EntryDetailView(
              detail: detail,
              onEdit: {
                editorContext = EntryEditorContext(
                  detail: detail,
                  summary: store.entries.first { $0.path == detail.path }
                )
              },
              onDelete: { showDeleteConfirmation = true }
            )
          } else {
            ContentUnavailableView(
              "Secret auswählen",
              systemImage: "key.horizontal",
              description: Text("Wähle links einen Eintrag oder lege einen neuen an.")
            )
            .foregroundStyle(SymairaTheme.textSecondary)
          }
        }
        .navigationTitle(store.detail?.path ?? "Symaira Vault")
        .toolbar {
          ToolbarItemGroup {
            Button {
              editorContext = .create
            } label: {
              Label("Neues Secret", systemImage: "plus")
            }
            .help("Neues Secret anlegen")

            Button {
              Task { await store.refresh() }
            } label: {
              if store.isBusy {
                ProgressView().controlSize(.small)
              } else {
                Label("Aktualisieren", systemImage: "arrow.clockwise")
              }
            }
            .disabled(store.isBusy)
            .help("Vault aktualisieren")

            Button {
              Task { await store.lock() }
            } label: {
              Label("Sperren", systemImage: "lock.fill")
            }
            .help("Vault sperren")
          }
        }
      }
      .navigationSplitViewStyle(.balanced)
      .onChange(of: store.selectedPath) { _, path in
        Task { await store.load(path: path) }
      }
      .sheet(item: $editorContext) { context in
        EntryEditorView(context: context)
          .environment(store)
      }
      .confirmationDialog(
        "„\(store.selectedPath ?? "Secret")“ wirklich löschen?",
        isPresented: $showDeleteConfirmation,
        titleVisibility: .visible
      ) {
        Button("Endgültig löschen", role: .destructive) {
          Task { _ = await store.deleteSelected() }
        }
        Button("Abbrechen", role: .cancel) {}
      } message: {
        Text("Der verschlüsselte Eintrag wird aus dem Vault entfernt.")
      }
    }
  }

  private struct EntrySidebarRow: View {
    let entry: VaultEntrySummary

    var body: some View {
      HStack(spacing: 10) {
        Image(systemName: iconName)
          .foregroundStyle(SymairaTheme.goldPrimary)
          .frame(width: 20)
        VStack(alignment: .leading, spacing: 2) {
          Text(entry.title)
            .font(.body.weight(.medium))
            .lineLimit(1)
          HStack(spacing: 5) {
            if let type = entry.type, !type.isEmpty {
              Text(type.replacingOccurrences(of: "_", with: " "))
            }
            if let count = entry.fieldCount, count > 0 {
              Text("· \(count) Felder")
            }
          }
          .font(.caption2)
          .foregroundStyle(SymairaTheme.textMuted)
        }
        Spacer()
        if entry.autoRotate == true {
          Image(systemName: "arrow.triangle.2.circlepath")
            .font(.caption2)
            .foregroundStyle(SymairaTheme.icePrimary)
            .help("Rotation aktiviert")
        }
      }
      .padding(.vertical, 3)
    }

    private var iconName: String {
      switch entry.type {
      case "api_key", "bearer_token": return "key.fill"
      case "ssh_key", "certificate": return "network.badge.shield.half.filled"
      case "database_url": return "cylinder.fill"
      case "totp_seed": return "timer"
      default: return "lock.fill"
      }
    }
  }

  private struct RuntimeFooter: View {
    @Environment(VaultStore.self) private var store

    var body: some View {
      VStack(spacing: 8) {
        Divider()
        HStack(spacing: 8) {
          Circle()
            .fill(SymairaTheme.goldPrimary)
            .frame(width: 7, height: 7)
          VStack(alignment: .leading, spacing: 1) {
            Text("\(store.entries.count) Secrets")
              .font(.caption.weight(.medium))
            Text(store.runtime?.version ?? "symvault")
              .font(.caption2.monospaced())
              .foregroundStyle(SymairaTheme.textMuted)
          }
          Spacer()
        }
        .padding(.horizontal, 14)
        .padding(.bottom, 10)
      }
      .background(.ultraThinMaterial)
    }
  }
#endif
