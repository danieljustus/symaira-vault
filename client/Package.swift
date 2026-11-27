// swift-tools-version: 6.0
import Foundation
import PackageDescription

// Dependabot loads this manifest in a clean checkout where the git-ignored
// XCFramework build output is absent. Declare the binary target only when the
// file exists; a local build with the framework keeps the same target graph.
let vaultCoreFrameworkPath = ".build/mobilecore/SymvaultFFI.xcframework"
let hasVaultCoreFramework = FileManager.default.fileExists(
    // Context.packageDirectory, not the cwd: xcodebuild -project evaluates the
    // manifest from another working directory.
    atPath: Context.packageDirectory + "/" + vaultCoreFrameworkPath
)

let package = Package(
    name: "SymvaultClient",
    defaultLocalization: "en",
    platforms: [
        .macOS(.v14),
        .iOS(.v17),
    ],
    products: [
        .library(name: "SymvaultKit", targets: ["SymvaultKit"]),
        .library(name: "SymvaultFeature", targets: ["SymvaultFeature"]),
        .library(name: "SymvaultIOS", targets: ["SymvaultIOS"]),
        .library(name: "SymvaultFFI", targets: ["SymvaultFFI"]),
    ],
    dependencies: [
        .package(url: "https://github.com/danieljustus/symaira-corekit.git", exact: "0.27.1"),
    ],
    targets: [
        // Rust vault core (crates/symvault-ffi): the XCFramework built by
        // scripts/build-vaultcore.sh (ios-arm64, ios-arm64-simulator,
        // macos-arm64). It is git-ignored build output. Its `CSymvaultFFI`
        // module is the C header; ADR 0031. Declared below only when present.
        // Swift wrapper over the C ABI. The sources are the reviewed ones in
        // crates/symvault-ffi/swift (reached through the Sources/SymvaultFFI
        // symlink; SwiftPM does not accept a target path outside the package).
        .target(
            name: "SymvaultFFI",
            dependencies: hasVaultCoreFramework ? ["CSymvaultFFI"] : [],
            path: "Sources/SymvaultFFI",
            // The wrapper is written for Swift 5 mode (package tools 5.9).
            swiftSettings: [.swiftLanguageMode(.v5)],
            // libiconv: the Rust standard library needs it.
            linkerSettings: [.linkedLibrary("iconv")]
        ),
        .target(
            name: "SymvaultKit",
            dependencies: [
                .product(name: "SymairaCLIRunner", package: "symaira-corekit"),
                .product(name: "SymairaToolKit", package: "symaira-corekit"),
                .target(name: "SymvaultFFI", condition: .when(platforms: [.iOS])),
            ]
        ),
        .target(
            name: "SymvaultFeature",
            dependencies: [
                "SymvaultKit",
                .product(name: "SymairaTheme", package: "symaira-corekit"),
            ],
            // English source, German translations (Localizable.xcstrings).
            resources: [.process("Resources")]
        ),
        .testTarget(
            name: "SymvaultKitTests",
            dependencies: ["SymvaultKit"]
        ),
        .target(
            name: "SymvaultIOS",
            dependencies: ["SymvaultFFI"],
            path: "Sources/SymvaultIOS",
            exclude: [
                // App-bundle resource (see project.yml); not a SwiftPM resource.
                "PrivacyInfo.xcprivacy",
                // App-bundle String Catalog, compiled by the app target.
                "Localizable.xcstrings",
                "ApprovalsListView.swift",
                "EnrollView.swift",
                "EntryDetailView.swift",
                "EntryListView.swift",
                "PairingScanView.swift",
                "SymvaultApp.swift",
                "UnlockView.swift",
                "VaultStore.swift",
            ]
        ),
        .testTarget(
            name: "SymvaultIOSTests",
            dependencies: ["SymvaultIOS", "SymvaultFFI"]
        ),
    ]
)

if hasVaultCoreFramework {
    // Keep the binary target first, as it was before the guard.
    package.targets.insert(
        .binaryTarget(name: "CSymvaultFFI", path: vaultCoreFrameworkPath),
        at: 0
    )
}
