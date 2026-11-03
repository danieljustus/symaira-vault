import Foundation
import SymvaultFFI

/// Where the Rust core puts the verified pre-migration backup (decision D1) of
/// a Go-created vault before its first write.
///
/// An iOS app has no `$HOME`/`$XDG_STATE_HOME`, so the host must name the
/// directory (a scoped `SymvaultFFI` override, ADR 0031). The backup holds the same
/// encrypted vault files as the vault, so it must not travel to iCloud/iTunes
/// backups a second time, and it must not live in `Caches` (the system may
/// purge it, which would defeat a safety net). The directory is therefore in
/// Application Support with `isExcludedFromBackup` set, and the core is only
/// pointed at it once that exclusion is verified.
public enum MobileVaultBackup {
    /// Application Support/`symaira-vault-backups`, inside the app container.
    public static func defaultDirectory(fileManager: FileManager = .default) throws -> URL {
        let support = try fileManager.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true)
        return support.appendingPathComponent("symaira-vault-backups", isDirectory: true)
    }

    /// Creates `directory` (`0700`), marks it excluded from backup, reads the
    /// flag and permissions back before the caller uses the directory. Throws
    /// before any vault operation when a step fails.
    static func prepare(_ directory: URL, fileManager: FileManager = .default) throws {
        var url = directory.standardizedFileURL
        try fileManager.createDirectory(
            at: url, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        let attributes = try fileManager.attributesOfItem(atPath: url.path)
        guard attributes[.type] as? FileAttributeType == .typeDirectory else {
            throw MobileVaultCoreError.frameworkError("backup path is not a directory: \(url.path)")
        }
        try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
        let checked = try fileManager.attributesOfItem(atPath: url.path)
        guard checked[.type] as? FileAttributeType == .typeDirectory,
              (checked[.posixPermissions] as? NSNumber)?.intValue == 0o700 else {
            throw MobileVaultCoreError.frameworkError("backup directory permissions are not 0700: \(url.path)")
        }
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try url.setResourceValues(values)
        let readBack = try url.resourceValues(forKeys: [.isExcludedFromBackupKey])
        guard readBack.isExcludedFromBackup == true else {
            throw MobileVaultCoreError.frameworkError(
                "backup directory could not be excluded from iCloud backup: \(url.path)")
        }
    }
}
