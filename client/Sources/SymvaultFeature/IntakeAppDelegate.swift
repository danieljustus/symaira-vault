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

    public func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
      false
    }
  }
#endif
