// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "SymvaultClient",
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
        .package(url: "https://github.com/danieljustus/symaira-appkit.git", exact: "0.10.0"),
    ],
    targets: [
        // Rust vault core (crates/symvault-ffi): the XCFramework built by
        // scripts/build-vaultcore.sh (ios-arm64, ios-arm64-simulator,
        // macos-arm64). It is git-ignored build output. Its `CSymvaultFFI`
        // module is the C header; ADR 0031.
        .binaryTarget(
            name: "CSymvaultFFI",
            path: ".build/mobilecore/SymvaultFFI.xcframework"
        ),
        // Swift wrapper over the C ABI. The sources are the reviewed ones in
        // crates/symvault-ffi/swift (reached through the Sources/SymvaultFFI
        // symlink; SwiftPM does not accept a target path outside the package).
        .target(
            name: "SymvaultFFI",
            dependencies: ["CSymvaultFFI"],
            path: "Sources/SymvaultFFI",
            // The wrapper is written for Swift 5 mode (package tools 5.9).
            swiftSettings: [.swiftLanguageMode(.v5)],
            // libiconv: the Rust standard library needs it.
            linkerSettings: [.linkedLibrary("iconv")]
        ),
        .target(
            name: "SymvaultKit",
            dependencies: [
                .product(name: "SymairaCLIRunner", package: "symaira-appkit"),
                .product(name: "SymairaToolKit", package: "symaira-appkit"),
                .target(name: "SymvaultFFI", condition: .when(platforms: [.iOS])),
            ]
        ),
        .target(
            name: "SymvaultFeature",
            dependencies: [
                "SymvaultKit",
                .product(name: "SymairaTheme", package: "symaira-appkit"),
            ]
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
