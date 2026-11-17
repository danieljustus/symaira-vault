#if os(macOS)
  import AppKit
  import Foundation

  /// Bridges Finder "Open With" / drag-onto-icon file opens into the intake
  /// flow. The app is an intake destination, not a generic viewer: opened
  /// files are forwarded to the intake sheet for review, never auto-imported.
  public final class IntakeAppDelegate: NSObject, NSApplicationDelegate {
    public static let openFilesNotification = Notification.Name("SymvaultIntakeOpenFiles")

    public func application(_ application: NSApplication, open urls: [URL]) {
      let securityScoped = urls.map { url -> URL in
        if url.startAccessingSecurityScopedResource() {
          return url
        }
        return url
      }
      NotificationCenter.default.post(name: Self.openFilesNotification, object: securityScoped)
    }

    public func applicationDidFinishLaunching(_ notification: Notification) {
      NSApp.servicesProvider = self
    }

    /// macOS service "Add to Symaira Vault" (`NSServices` in the app's
    /// Info.plist): receives the text selected in any app. It is only handed
    /// to the confirmation sheet; nothing is stored before the user confirms.
    @MainActor
    @objc public func addSelectionToVault(
      _ pasteboard: NSPasteboard, userData: String,
      error: AutoreleasingUnsafeMutablePointer<NSString>
    ) {
      guard let text = pasteboard.string(forType: .string),
        !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
      else {
        error.pointee = L("The selection contains no text.") as NSString
        return
      }
      SelectionInbox.shared.pending = text
      // Reopening the own bundle brings the app forward and, with no window
      // open, makes SwiftUI create one.
      NSWorkspace.shared.open(Bundle.main.bundleURL)
    }

    public func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
      false
    }
  }
#endif
