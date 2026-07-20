// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "SymvaultClient",
    platforms: [
        .macOS(.v14),
    ],
    products: [
        .library(name: "SymvaultKit", targets: ["SymvaultKit"]),
        .library(name: "SymvaultFeature", targets: ["SymvaultFeature"]),
    ],
    dependencies: [
        .package(url: "https://github.com/danieljustus/symaira-appkit.git", exact: "0.4.0"),
    ],
    targets: [
        .target(
            name: "SymvaultKit",
            dependencies: [
                .product(name: "SymairaCLIRunner", package: "symaira-appkit"),
                .product(name: "SymairaToolKit", package: "symaira-appkit"),
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
    ]
)
