#if os(macOS)
  import SwiftUI
  import SymairaTheme
  import SymvaultKit

  /// New Entry and Edit Entry sheet: one scaffold, Esc cancels, Return saves.
  struct EntryEditorView: View {
    private enum Field: Hashable { case path, username, url, secret, notes, hint }

    let context: EntryEditorContext
    @Environment(VaultStore.self) private var store
    @Environment(\.dismiss) private var dismiss
    @State private var draft: VaultDraft
    @State private var passwordLength = 24
    @State private var useSymbols = true
    @State private var isGenerating = false
    @State private var isSaving = false
    @State private var pathError: String?
    @State private var secretError: String?
    @FocusState private var focus: Field?

    private static let types: [(value: String, label: String)] = [
      (value: "password", label: L("Password")), (value: "api_key", label: L("API Key")),
      (value: "bearer_token", label: L("Bearer Token")),
      (value: "basic_auth", label: L("Basic Auth")),
      (value: "ssh_key", label: L("SSH Key")), (value: "certificate", label: L("Certificate")),
      (value: "database_url", label: L("Database URL")), (value: "custom", label: L("Custom")),
    ]

    init(context: EntryEditorContext) {
      self.context = context
      if let detail = context.detail {
        _draft = State(
          initialValue: VaultDraft(
            detail: detail, type: context.summary?.type, usageHint: context.summary?.usageHint))
      } else {
        _draft = State(initialValue: VaultDraft())
      }
    }

    var body: some View {
      SymairaSheetScaffold(
        title: isEditing ? L("Edit Entry") : L("New Entry"),
        dismiss: { dismiss() },
        primaryTitle: isSaving ? L("Saving…") : L("Save Entry"),
        primaryDisabled: isSaving || store.isBusy,
        primary: save
      ) {
        SymairaFormSection(
          L("Entry"),
          footer: isEditing ? L("The path of an existing entry cannot change here.") : nil
        ) {
          SymairaFormRow(
            L("Path"),
            description: pathError == nil ? L("Group and name, separated by a slash.") : nil
          ) {
            VStack(alignment: .trailing, spacing: SymairaSpacing.xSmall) {
              field("work/github", text: $draft.path, focus: .path)
                .disabled(isEditing)
              errorText(pathError)
            }
          }
          SymairaFormDivider()
          SymairaFormRow(L("Username")) {
            field("name@example.com", text: $draft.username, focus: .username)
          }
          SymairaFormDivider()
          SymairaFormRow(L("URL")) { field("https://example.com", text: $draft.url, focus: .url) }
        }

        SymairaFormSection(
          L("Secret"), footer: L("Generated passwords come from symvault on this Mac.")
        ) {
          SymairaFormRow(L("Password or Secret")) {
            VStack(alignment: .trailing, spacing: SymairaSpacing.xSmall) {
              SecureField(L("Required"), text: $draft.secret)
                .textFieldStyle(.symaira(isFocused: focus == .secret))
                .focused($focus, equals: .secret)
                .frame(width: 260)
                .accessibilityLabel(L("Password or secret"))
              errorText(secretError)
            }
          }
          SymairaFormDivider()
          SymairaFormRow(L("Length")) {
            Stepper(value: $passwordLength, in: 12...128, step: 4) {
              Text(L("%d characters", passwordLength)).symairaText(.body).monospacedDigit()
            }
            .accessibilityLabel(L("Password length"))
            .accessibilityValue(L("%d characters", passwordLength))
          }
          SymairaFormDivider()
          SymairaFormRow(L("Include Symbols")) {
            Toggle(isOn: $useSymbols) { EmptyView() }
              .toggleStyle(.symairaSwitch)
              .centeredOnFormLabel()
              .accessibilityLabel(L("Include symbols"))
          }
          HStack {
            Spacer()
            Button(action: generatePassword) {
              Label(isGenerating ? L("Generating…") : L("Generate Password"), symairaIcon: .magic)
                .frame(minWidth: 170)
            }
            .symairaButtonStyle(.secondary)
            .disabled(isGenerating)
          }
          .padding(.bottom, SymairaSpacing.small)
        }

        SymairaFormSection(L("Notes")) {
          TextField(L("Optional"), text: $draft.notes, axis: .vertical)
            .lineLimit(3...8)
            .textFieldStyle(.symaira(isFocused: focus == .notes))
            .focused($focus, equals: .notes)
            .accessibilityLabel(L("Notes"))
            .padding(.vertical, SymairaSpacing.small)
        }

        if !isEditing {
          SymairaFormSection(
            L("Classification"), footer: L("The hint tells local AI agents what the entry is for.")
          ) {
            SymairaFormRow(L("Type")) {
              SymairaFilterMenu(L("Type"), selection: $draft.type, options: Self.types)
            }
            SymairaFormDivider()
            SymairaFormRow(L("Usage Hint")) {
              field("Optional", text: $draft.usageHint, focus: .hint)
            }
          }

          SymairaFormSection(
            L("One-Time Code"),
            footer: L("Optional. Paste the Base32 secret from the service's setup page.")
          ) {
            SymairaFormRow(L("Base32 Secret")) {
              SecureField(L("Optional"), text: $draft.totpSecret)
                .textFieldStyle(.symaira)
                .frame(width: 260)
                .accessibilityLabel(L("TOTP Base32 secret"))
            }
            SymairaFormDivider()
            SymairaFormRow(L("Issuer")) {
              TextField(L("Example Inc."), text: $draft.totpIssuer).textFieldStyle(.symaira).frame(
                width: 260)
            }
            SymairaFormDivider()
            SymairaFormRow(L("Account")) {
              TextField(L("name@example.com"), text: $draft.totpAccount).textFieldStyle(.symaira)
                .frame(width: 260)
            }
          }
        }

        if let message = store.errorMessage, isSaving == false, saveAttempted {
          SymairaNotice(message: message, tone: .critical) { store.clearError() }
        }
      }
      .frame(width: 620, height: isEditing ? 620 : 720)
      .onAppear { focus = isEditing ? .username : .path }
    }

    @State private var saveAttempted = false

    private var isEditing: Bool { context.detail != nil }

    private func field(_ placeholder: String, text: Binding<String>, focus value: Field)
      -> some View
    {
      TextField(placeholder, text: text)
        .textFieldStyle(.symaira(isFocused: focus == value))
        .focused($focus, equals: value)
        .frame(width: 260)
    }

    @ViewBuilder
    private func errorText(_ message: String?) -> some View {
      if let message {
        Text(message)
          .symairaText(.caption, respectsForeground: false)
          .foregroundStyle(SymairaTokens.critical)
      }
    }

    private func generatePassword() {
      isGenerating = true
      Task {
        if let password = await store.generatePassword(length: passwordLength, symbols: useSymbols)
        {
          draft.secret = password
          secretError = nil
        }
        isGenerating = false
      }
    }

    private func save() {
      draft.path = draft.path.trimmingCharacters(in: .whitespacesAndNewlines)
      pathError = draft.path.isEmpty ? L("Enter a path, for example work/github.") : nil
      secretError = draft.secret.isEmpty ? L("Enter a secret or generate one.") : nil
      if pathError != nil {
        focus = .path
        return
      }
      if secretError != nil {
        focus = .secret
        return
      }

      isSaving = true
      saveAttempted = true
      store.clearError()
      Task {
        let success: Bool
        if let detail = context.detail {
          success = await store.update(draft, original: detail)
        } else {
          success = await store.create(draft)
        }
        isSaving = false
        if success { dismiss() }
      }
    }
  }
#endif
