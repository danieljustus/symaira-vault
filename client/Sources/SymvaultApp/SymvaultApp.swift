import SwiftUI
import SymvaultFeature

@main
struct SymvaultApp: App {
  @NSApplicationDelegateAdaptor(IntakeAppDelegate.self) private var appDelegate
  @State private var model = VaultAppModel()

  var body: some Scene {
    VaultScenes(model: model)
  }
}
