import Foundation

/// Localized text of the iOS app: English source, German in
/// `Localizable.xcstrings` in the app bundle. The language follows the
/// system's preferred languages; English is the fallback for a missing key.
func L(_ key: String) -> String {
    Bundle.main.localizedString(forKey: key, value: key, table: nil)
}

/// Localized text with values filled in, e.g. `L("Hide %@", name)`.
func L(_ key: String, _ arguments: CVarArg...) -> String {
    String(format: L(key), locale: .current, arguments: arguments)
}
