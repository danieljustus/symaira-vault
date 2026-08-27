import SwiftUI
import SymvaultFeature

@main
struct SymvaultApp: App {
  @NSApplicationDelegateAdaptor(IntakeAppDelegate.self) private var appDelegate

  var body: some Scene {
    WindowGroup("Symaira Vault") {
      SymvaultModuleView()
        .frame(minWidth: 900, minHeight: 620)
    }
    .defaultSize(width: 1120, height: 760)
    .windowStyle(.titleBar)
    .windowToolbarStyle(.unified)
    .commands {
      CommandGroup(after: .newItem) {
        Button("Credential-Dateien aufnehmen …") {
          NotificationCenter.default.post(name: IntakeAppDelegate.openFilesNotification, object: [URL]())
        }
        .keyboardShortcut("i", modifiers: [.command, .shift])
      }
    }

    Settings {
      VStack(spacing: 10) {
        Image(systemName: "lock.shield.fill")
          .font(.system(size: 34, weight: .light))
        Text("Symaira Vault")
          .font(.title2.weight(.semibold))
        Text("Native Oberfläche für die lokale symvault Runtime")
          .foregroundStyle(.secondary)
      }
      .padding(28)
      .frame(width: 420)
    }
  }
}
