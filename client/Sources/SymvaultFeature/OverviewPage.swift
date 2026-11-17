#if os(macOS)
  import SwiftUI
  import SymairaTheme
  import SymvaultKit

  /// Screen card. Destination: Overview (1 of 3). Job: see the state of the
  /// vault at a glance and start the next task; primary action New Entry.
  /// Data: the entry list and runtime info already loaded by `VaultStore`
  /// (`symvault list`, `version`), refreshed on unlock and ⌘R. States: gate
  /// covers connecting, missing, failed and locked; empty vault shows an empty
  /// state with New Entry. Density: dashboard tiles plus cards. Platform:
  /// macOS workspace; no preference keys.
  struct OverviewPage: View {
    let model: VaultAppModel
    @Environment(VaultStore.self) private var store

    var body: some View {
      SymairaPage(title: L("Overview"), subtitle: L("The state of your local vault")) {
        Spacer()
        Button(action: model.lock) { Label(L("Lock Vault"), symairaIcon: .lock) }
          .symairaButtonStyle(.secondary)
        SymairaIconButton(L("Refresh"), icon: .refresh, action: model.refresh)
          .disabled(store.isBusy)
        Button(action: model.newEntry) { Label(L("New Entry"), symairaIcon: .add) }
          .symairaButtonStyle(.primary)
      } content: {
        VaultNotices()
        if store.entries.isEmpty {
          SymairaPageEmpty(
            icon: .key,
            title: L("No Entries"),
            message: L(
              "The vault is empty. Create an entry, or import credential files from Import.")
          )
        } else {
          tiles
          groups
        }
        runtimeCard
      }
    }

    private var tiles: some View {
      HStack(spacing: SymairaSpacing.medium) {
        SymairaStatTile(
          value: "\(store.entries.count)", label: L("Entries"), detail: L("In this profile"))
        SymairaStatTile(
          value: "\(groupCounts.count)", label: L("Groups"), detail: L("First part of the path"))
        SymairaStatTile(value: "\(typeCount)", label: L("Types"), detail: L("Distinct entry types"))
        SymairaStatTile(
          value: "\(rotatingCount)", label: L("Auto-Rotate"), detail: L("Entries with rotation on"))
      }
      .topoProtected()
    }

    private var groups: some View {
      VStack(alignment: .leading, spacing: SymairaSpacing.small) {
        Text(L("LARGEST GROUPS")).symairaText(.sectionLabel)
        ForEach(Array(largestGroups.enumerated()), id: \.element.name) { index, group in
          if index > 0 { SymairaFormDivider() }
          GroupRow(name: group.name, count: group.count) { show(group: group.name) }
        }
        if groupCounts.count > Self.groupLimit {
          SymairaFormDivider()
          HStack {
            Text(L("%d more groups", groupCounts.count - Self.groupLimit)).symairaText(.caption)
            Spacer()
            Button(L("Show All Entries")) { show(group: nil) }
              .symairaButtonStyle(.secondary)
          }
          .padding(.top, SymairaSpacing.xSmall)
        }
      }
      .frame(maxWidth: .infinity, alignment: .leading)
      .symairaCard()
    }

    private func show(group: String?) {
      store.searchText = group.map { $0 == "General" ? "" : "\($0)/" } ?? ""
      model.destination = .entries
    }

    private var runtimeCard: some View {
      VStack(alignment: .leading, spacing: SymairaSpacing.small) {
        Text(L("RUNTIME")).symairaText(.sectionLabel)
        if let runtime = store.runtime {
          detailRow(L("Version"), runtime.version ?? L("Unknown"))
          SymairaFormDivider()
          detailRow(L("Source"), runtime.source)
          SymairaFormDivider()
          detailRow(L("Path"), runtime.path)
        } else {
          Text(L("No runtime information loaded.")).symairaText(.caption)
        }
      }
      .frame(maxWidth: .infinity, alignment: .leading)
      .symairaCard()
    }

    private func detailRow(_ label: String, _ value: String) -> some View {
      HStack(alignment: .firstTextBaseline) {
        Text(label).symairaText(.secondary).frame(width: 90, alignment: .leading)
        Text(verbatim: value)
          .symairaText(.monoSmall)
          .foregroundStyle(SymairaTokens.ink)
          .textSelection(.enabled)
          .lineLimit(1)
          .truncationMode(.middle)
          .help(value)
        Spacer(minLength: 0)
      }
    }

    private var groupCounts: [(name: String, count: Int)] {
      Dictionary(grouping: store.entries, by: \.group)
        .map { (name: $0.key, count: $0.value.count) }
        .sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    private static let groupLimit = 8

    /// A short list, not a 50-row directory: the table on Entries covers the rest (LAYOUT-4).
    private var largestGroups: [(name: String, count: Int)] {
      Array(
        groupCounts.sorted {
          $0.count == $1.count
            ? $0.name.localizedStandardCompare($1.name) == .orderedAscending : $0.count > $1.count
        }
        .prefix(Self.groupLimit))
    }

    private var typeCount: Int {
      Set(store.entries.compactMap { $0.type?.isEmpty == false ? $0.type : nil }).count
    }

    private var rotatingCount: Int {
      store.entries.filter { $0.autoRotate == true }.count
    }
  }

  /// One group in the overview list; opens Entries filtered to that group.
  private struct GroupRow: View {
    let name: String
    let count: Int
    let action: () -> Void
    @State private var isHovered = false

    var body: some View {
      Button(action: action) {
        HStack {
          Text(verbatim: name == "General" ? L("General") : name).symairaText(.body)
          Spacer()
          Text(countLabel).symairaText(.secondary).monospacedDigit()
          SymairaIconView(.forward, size: 14)
            .foregroundStyle(SymairaTokens.ink3)
            .accessibilityHidden(true)
        }
        .padding(.vertical, SymairaSpacing.xSmall)
        .padding(.horizontal, SymairaSpacing.small)
        .background(
          RoundedRectangle(cornerRadius: SymairaRadius.control, style: .continuous)
            .fill(isHovered ? SymairaTokens.raised : .clear)
        )
        .contentShape(Rectangle())
      }
      .buttonStyle(.plain)
      .onHover { isHovered = $0 }
      .accessibilityLabel(L("Show %@, %@", name, countLabel))
      .contextMenu { Button(L("Show in Entries"), action: action) }
    }

    private var countLabel: String { count == 1 ? L("1 entry") : L("%d entries", count) }
  }
#endif
