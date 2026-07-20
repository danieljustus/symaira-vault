#if os(macOS)
  import AppKit
  import Foundation
  import Observation
  import SymvaultKit

  @MainActor
  @Observable
  public final class VaultStore {
    public enum Availability: Equatable {
      case checking
      case missing
      case locked
      case ready
      case failed(String)
    }

    public var availability: Availability = .checking
    public var runtime: VaultRuntimeInfo?
    public var entries: [VaultEntrySummary] = []
    public var selectedPath: String?
    public var detail: VaultEntryDetail?
    public var detailLoadedAt = Date()
    public var searchText = ""
    public var isBusy = false
    public var isDetailLoading = false
    public var errorMessage: String?
    public var clipboardNotice: String?
    public var profile = ""

    @ObservationIgnored private let client: VaultClient
    @ObservationIgnored private var clipboardClearTask: Task<Void, Never>?

    public init(client: VaultClient = VaultClient()) {
      self.client = client
    }

    public var filteredEntries: [VaultEntrySummary] {
      guard !searchText.isEmpty else { return entries }
      return entries.filter {
        $0.path.localizedCaseInsensitiveContains(searchText)
          || ($0.type?.localizedCaseInsensitiveContains(searchText) ?? false)
          || ($0.usageHint?.localizedCaseInsensitiveContains(searchText) ?? false)
      }
    }

    public var groupedEntries: [(String, [VaultEntrySummary])] {
      Dictionary(grouping: filteredEntries, by: \.group)
        .map {
          (
            $0.key,
            $0.value.sorted { $0.path.localizedStandardCompare($1.path) == .orderedAscending }
          )
        }
        .sorted { $0.0.localizedStandardCompare($1.0) == .orderedAscending }
    }

    public func refresh() async {
      isBusy = true
      errorMessage = nil
      defer { isBusy = false }

      guard let runtime = await client.detect() else {
        self.runtime = nil
        entries = []
        detail = nil
        availability = .missing
        return
      }
      self.runtime = runtime

      if let schema = runtime.schemaVersion,
        schema != 0,
        schema != VaultClient.expectedSchemaVersion
      {
        availability = .failed(
          "Die installierte Runtime nutzt Schema \(schema); diese App erwartet Schema \(VaultClient.expectedSchemaVersion)."
        )
        return
      }

      do {
        guard try await client.isUnlocked(profile: activeProfile) else {
          entries = []
          detail = nil
          availability = .locked
          return
        }
        entries = try await client.listEntries(profile: activeProfile)
        availability = .ready

        if let selectedPath, entries.contains(where: { $0.path == selectedPath }) {
          await load(path: selectedPath)
        } else {
          self.selectedPath = entries.first?.path
          if let selectedPath = self.selectedPath {
            await load(path: selectedPath)
          } else {
            detail = nil
          }
        }
      } catch {
        handle(error)
      }
    }

    public func load(path: String?) async {
      guard let path, availability == .ready else {
        detail = nil
        return
      }
      isDetailLoading = true
      defer { isDetailLoading = false }
      do {
        detail = try await client.entry(path: path, profile: activeProfile)
        detailLoadedAt = Date()
      } catch {
        handle(error)
      }
    }

    public func unlock(passphrase: String, ttl: String) async -> Bool {
      guard !passphrase.isEmpty else {
        errorMessage = "Bitte gib die Vault-Passphrase ein."
        return false
      }
      isBusy = true
      errorMessage = nil
      do {
        try await client.unlock(passphrase: passphrase, ttl: ttl, profile: activeProfile)
        isBusy = false
        await refresh()
        return availability == .ready
      } catch {
        isBusy = false
        handle(error)
        return false
      }
    }

    public func lock() async {
      isBusy = true
      do {
        try await client.lock(profile: activeProfile)
        entries = []
        detail = nil
        availability = .locked
      } catch {
        handle(error)
      }
      isBusy = false
    }

    public func create(_ draft: VaultDraft) async -> Bool {
      isBusy = true
      errorMessage = nil
      do {
        try await client.create(draft, profile: activeProfile)
        selectedPath = draft.path
        isBusy = false
        await refresh()
        return availability == .ready
      } catch {
        isBusy = false
        handle(error)
        return false
      }
    }

    public func update(_ draft: VaultDraft, original: VaultEntryDetail) async -> Bool {
      isBusy = true
      errorMessage = nil
      do {
        try await client.update(
          path: original.path, original: original, draft: draft, profile: activeProfile)
        isBusy = false
        await refresh()
        return availability == .ready
      } catch {
        isBusy = false
        handle(error)
        return false
      }
    }

    public func deleteSelected() async -> Bool {
      guard let selectedPath else { return false }
      isBusy = true
      do {
        try await client.delete(path: selectedPath, profile: activeProfile)
        self.selectedPath = nil
        detail = nil
        isBusy = false
        await refresh()
        return true
      } catch {
        isBusy = false
        handle(error)
        return false
      }
    }

    public func generatePassword(length: Int, symbols: Bool) async -> String? {
      do {
        return try await client.generatePassword(
          length: length, symbols: symbols, profile: activeProfile)
      } catch {
        handle(error)
        return nil
      }
    }

    public func copy(_ value: String, label: String) {
      let pasteboard = NSPasteboard.general
      pasteboard.clearContents()
      pasteboard.setString(value, forType: .string)
      let expectedChangeCount = pasteboard.changeCount
      clipboardNotice = "\(label) kopiert · wird in 30 s geleert"

      clipboardClearTask?.cancel()
      clipboardClearTask = Task { [weak self] in
        try? await Task.sleep(for: .seconds(30))
        guard !Task.isCancelled else { return }
        if pasteboard.changeCount == expectedChangeCount,
          pasteboard.string(forType: .string) == value
        {
          pasteboard.clearContents()
        }
        self?.clipboardNotice = nil
      }
    }

    public func clearError() {
      errorMessage = nil
    }

    private var activeProfile: String? {
      let trimmed = profile.trimmingCharacters(in: .whitespacesAndNewlines)
      return trimmed.isEmpty ? nil : trimmed
    }

    private func handle(_ error: Error) {
      let message = error.localizedDescription
      errorMessage = message
      if message.localizedCaseInsensitiveContains("locked")
        || message.localizedCaseInsensitiveContains("active session")
      {
        availability = .locked
      }
    }
  }
#endif
