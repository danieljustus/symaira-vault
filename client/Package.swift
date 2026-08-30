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
    ],
    dependencies: [
        .package(url: "https://github.com/danieljustus/symaira-appkit.git", exact: "0.10.0"),
    ],
    targets: [
        .binaryTarget(
            name: "Vaultcore",
            path: ".build/mobilecore/Vaultcore.xcframework"
        ),
        .target(
            name: "SymvaultKit",
            dependencies: [
                .product(name: "SymairaCLIRunner", package: "symaira-appkit"),
                .product(name: "SymairaToolKit", package: "symaira-appkit"),
                .target(name: "Vaultcore", condition: .when(platforms: [.iOS])),
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
            dependencies: [],
            path: "Sources/SymvaultIOS",
            exclude: [
                "ApprovalsListView.swift",
                "EnrollView.swift",
                "EntryDetailView.swift",
                "EntryListView.swift",
                "MobileVaultCore.swift",
                "PairingScanView.swift",
                "SymvaultApp.swift",
                "UnlockView.swift",
                "VaultStore.swift",
            ]
        ),
        .testTarget(
            name: "SymvaultIOSTests",
            dependencies: ["SymvaultIOS"]
        ),
    ]
)
