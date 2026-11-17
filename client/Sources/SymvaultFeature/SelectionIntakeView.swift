#if os(macOS)
  import Observation
  import SwiftUI
  import SymairaTheme
  import SymvaultKit

  /// Text handed over by the macOS service "Add to Symaira Vault" until
  /// the unlocked workspace presents it. In-process only, cleared on pickup.
  @MainActor
  @Observable
  public final class SelectionInbox {
    public static let shared = SelectionInbox()
    public var pending: String?
  }

  struct SelectionIntakeItem: Identifiable {
    let id = UUID()
    let text: String
  }

  /// Confirms one selected text as a vault entry: name, the field names the
  /// runtime recognized (never their values), one primary action.
  struct SelectionIntakeView: View {
    let text: String
    @Environment(VaultStore.self) private var store
    @Environment(\.dismiss) private var dismiss
    @State private var entryPath: String
    @State private var fields: [String]?
    @State private var errorMessage: String?
    @State private var isSaving = false
    @FocusState private var pathFocused: Bool

    init(text: String) {
      self.text = text
      _entryPath = State(initialValue: SelectionIntake.suggestedEntryPath(for: text))
    }

    var body: some View {
      SymairaSheetScaffold(
        title: L("Save Selection"),
        dismiss: { dismiss() },
        primaryTitle: isSaving ? L("Saving…") : L("Save Entry"),
        primaryDisabled: !canSave,
        primary: save
      ) {
        SymairaFormSection(L("Entry"), footer: pathHint) {
          SymairaFormRow(L("Path"), description: L("Group and name, for example hosting/cloud86.")) {
            TextField(L("hosting/cloud86"), text: $entryPath)
              .textFieldStyle(.symaira(isFocused: pathFocused))
              .focused($pathFocused)
              .frame(width: 250)
              .accessibilityLabel(L("Entry path"))
              .onSubmit(save)
          }
        }

        SymairaFormSection(
          L("Recognized Fields"),
          footer: L("Values are never shown here. Lines that are not recognized stay in the entry as a note.")
        ) {
          if let fields {
            if fields.isEmpty {
              SymairaFormRow(
                L("No Labeled Fields"),
                description:
                  L("Lines such as “Username: …” or “Password: …” are missing. The text is saved as an encrypted attachment.")
              )
            } else {
              ForEach(Array(fields.enumerated()), id: \.element) { index, field in
                if index > 0 { SymairaFormDivider() }
                SymairaFormRow(L(SelectionIntake.fieldTitle(field))) {
                  SymairaStatusLabel(L("Recognized"), tone: .positive)
                }
              }
            }
          } else if errorMessage == nil {
            SymairaLoadingState(L("Checking the selection…"))
              .frame(maxWidth: .infinity)
          }
        }

        if let errorMessage {
          SymairaNotice(message: errorMessage, tone: .critical)
        }
      }
      .frame(width: 540, height: 600)
      .task {
        do {
          fields = try await store.selectionFields(text)
        } catch {
          errorMessage = error.localizedDescription
        }
        pathFocused = true
      }
    }

    private var trimmedPath: String {
      entryPath.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private var pathExists: Bool {
      store.entries.contains { $0.path == trimmedPath }
    }

    private var pathHint: String? {
      pathExists ? L("An entry with this path already exists. Choose another path.") : nil
    }

    private var canSave: Bool {
      fields != nil && !isSaving && !trimmedPath.isEmpty && !pathExists
    }

    private func save() {
      guard canSave else { return }
      isSaving = true
      errorMessage = nil
      Task {
        do {
          try await store.saveSelection(text, entry: trimmedPath)
          dismiss()
        } catch {
          errorMessage = error.localizedDescription
          isSaving = false
        }
      }
    }
  }
#endif
