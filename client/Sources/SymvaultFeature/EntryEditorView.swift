#if os(macOS)
  import SwiftUI
  import SymairaTheme
  import SymvaultKit

  struct EntryEditorView: View {
    let context: EntryEditorContext
    @Environment(VaultStore.self) private var store
    @Environment(\.dismiss) private var dismiss
    @State private var draft: VaultDraft
    @State private var passwordLength = 24
    @State private var useSymbols = true
    @State private var isGenerating = false
    @State private var validationMessage: String?

    init(context: EntryEditorContext) {
      self.context = context
      if let detail = context.detail {
        _draft = State(
          initialValue: VaultDraft(
            detail: detail,
            type: context.summary?.type,
            usageHint: context.summary?.usageHint
          )
        )
      } else {
        _draft = State(initialValue: VaultDraft())
      }
    }

    var body: some View {
      NavigationStack {
        Form {
          Section("Eintrag") {
            TextField("Pfad, z. B. work/github", text: $draft.path)
              .disabled(isEditing)
            TextField("Benutzername", text: $draft.username)
            TextField("URL", text: $draft.url)
          }

          Section("Secret") {
            SecureField("Passwort oder Secret", text: $draft.secret)
            HStack {
              Stepper("\(passwordLength) Zeichen", value: $passwordLength, in: 12...128, step: 4)
              Toggle("Symbole", isOn: $useSymbols)
                .toggleStyle(.checkbox)
              Spacer()
              Button {
                generatePassword()
              } label: {
                if isGenerating {
                  ProgressView().controlSize(.small)
                } else {
                  Label("Generieren", systemImage: "wand.and.stars")
                }
              }
              .disabled(isGenerating)
            }
          }

          Section("Notizen") {
            TextEditor(text: $draft.notes)
              .font(.body)
              .frame(minHeight: 82)
          }

          if !isEditing {
            Section("Klassifikation") {
              Picker("Typ", selection: $draft.type) {
                Text("Passwort").tag("password")
                Text("API Key").tag("api_key")
                Text("Bearer Token").tag("bearer_token")
                Text("Basic Auth").tag("basic_auth")
                Text("SSH Key").tag("ssh_key")
                Text("Zertifikat").tag("certificate")
                Text("Datenbank-URL").tag("database_url")
                Text("Eigener Typ").tag("custom")
              }
              TextField("Hinweis für lokale AI-Agenten (optional)", text: $draft.usageHint)
            }

            Section("TOTP (optional)") {
              SecureField("Base32 Secret", text: $draft.totpSecret)
              TextField("Issuer", text: $draft.totpIssuer)
              TextField("Account", text: $draft.totpAccount)
            }
          }

          if let validationMessage {
            Section {
              Label(validationMessage, systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
            }
          }
        }
        .formStyle(.grouped)
        .scrollContentBackground(.hidden)
        .background(SymairaTheme.bgDark)
        .navigationTitle(isEditing ? "Secret bearbeiten" : "Neues Secret")
        .toolbar {
          ToolbarItem(placement: .cancellationAction) {
            Button("Abbrechen") { dismiss() }
          }
          ToolbarItem(placement: .confirmationAction) {
            Button("Sichern") { save() }
              .disabled(store.isBusy)
              .keyboardShortcut(.defaultAction)
          }
        }
      }
      .frame(width: 590, height: isEditing ? 520 : 680)
      .preferredColorScheme(.dark)
    }

    private var isEditing: Bool { context.detail != nil }

    private func generatePassword() {
      isGenerating = true
      Task {
        if let password = await store.generatePassword(length: passwordLength, symbols: useSymbols)
        {
          draft.secret = password
        }
        isGenerating = false
      }
    }

    private func save() {
      draft.path = draft.path.trimmingCharacters(in: .whitespacesAndNewlines)
      guard !draft.path.isEmpty else {
        validationMessage = "Der Pfad darf nicht leer sein."
        return
      }
      guard !draft.secret.isEmpty else {
        validationMessage = "Bitte gib ein Secret ein oder generiere eines."
        return
      }
      validationMessage = nil

      Task {
        let success: Bool
        if let detail = context.detail {
          success = await store.update(draft, original: detail)
        } else {
          success = await store.create(draft)
        }
        if success { dismiss() }
      }
    }
  }
#endif
