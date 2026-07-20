#if os(macOS)
  import SwiftUI
  import SymairaTheme

  struct UnlockView: View {
    @Environment(VaultStore.self) private var store
    @State private var passphrase = ""
    @State private var ttl = "15m"

    var body: some View {
      @Bindable var store = store

      VStack(spacing: 22) {
        VStack(spacing: 10) {
          ZStack {
            Circle()
              .fill(SymairaTheme.goldPrimary.opacity(0.08))
              .frame(width: 74, height: 74)
            Image(systemName: "lock.shield.fill")
              .font(.system(size: 32, weight: .light))
              .foregroundStyle(SymairaTheme.goldPrimary)
          }
          Text("Vault entsperren")
            .font(.largeTitle.weight(.semibold))
            .foregroundStyle(SymairaTheme.textPrimary)
          Text(
            "Die Passphrase wird direkt über stdin an die lokale Runtime übergeben und nicht gespeichert."
          )
          .font(.callout)
          .foregroundStyle(SymairaTheme.textSecondary)
          .multilineTextAlignment(.center)
          .frame(maxWidth: 420)
        }

        VStack(spacing: 12) {
          SecureField("Passphrase", text: $passphrase)
            .textFieldStyle(.roundedBorder)
            .font(.body)
            .onSubmit(unlock)

          HStack {
            TextField("Profil (optional)", text: $store.profile)
              .textFieldStyle(.roundedBorder)
            Picker("Sitzung", selection: $ttl) {
              Text("15 Minuten").tag("15m")
              Text("1 Stunde").tag("1h")
              Text("8 Stunden").tag("8h")
            }
            .pickerStyle(.menu)
            .frame(width: 150)
          }

          Button(action: unlock) {
            HStack(spacing: 8) {
              if store.isBusy {
                ProgressView().controlSize(.small)
              } else {
                Image(systemName: "lock.open.fill")
              }
              Text("Entsperren")
            }
            .frame(maxWidth: .infinity)
          }
          .buttonStyle(SymairaPrimaryButtonStyle())
          .disabled(passphrase.isEmpty || store.isBusy)
          .keyboardShortcut(.defaultAction)
        }
        .padding(20)
        .frame(width: 460)
        .glassmorphicPanel()

        if let runtime = store.runtime {
          HStack(spacing: 8) {
            Circle()
              .fill(SymairaTheme.goldPrimary)
              .frame(width: 6, height: 6)
            Text(runtime.version ?? "symvault")
            Text("·")
            Text(runtime.source)
          }
          .font(.caption.monospaced())
          .foregroundStyle(SymairaTheme.textMuted)
          .help(runtime.path)
        }
      }
      .padding(40)
    }

    private func unlock() {
      let submitted = passphrase
      passphrase = ""
      Task { _ = await store.unlock(passphrase: submitted, ttl: ttl) }
    }
  }
#endif
