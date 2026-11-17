import Foundation

/// Localized text of the app: English source, German in
/// `Resources/Localizable.xcstrings`. The language follows the system's
/// preferred languages; English is the fallback for a missing key.
func L(_ key: String) -> String {
  Bundle.module.localizedString(forKey: key, value: key, table: nil)
}

/// Localized text with values filled in, e.g. `L("%d entries", 12)`.
func L(_ key: String, _ arguments: CVarArg...) -> String {
  String(format: L(key), locale: .current, arguments: arguments)
}
