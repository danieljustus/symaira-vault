// swift-tools-version:5.9
//
// Swift binding and integration test for crates/symvault-ffi (FFI-001).
//
// Two ways to supply the Rust library; the default keeps the macOS
// `swift test` path of `make ffi-differential` unchanged.
//
// 1. Static library (default). Build it first (`make ffi-differential` does):
//
//        cargo build -p symvault-ffi --profile ffi --locked
//
//    then point SYMVAULT_FFI_LIB_DIR at the directory holding libsymvault_ffi.a
//    (default: <repo>/target/ffi, i.e. CARGO_TARGET_DIR=target). For an iOS
//    destination build the matching triple and use its directory, e.g.
//    <target>/aarch64-apple-ios-sim/ffi (see `make ffi-ios-simulator-test`).
//
// 2. XCFramework. `make ffi-xcframework` writes SymvaultFFI.xcframework (macOS
//    arm64, iOS device arm64, iOS Simulator arm64; header + `CSymvaultFFI`
//    module map inside). Set SYMVAULT_FFI_XCFRAMEWORK to its path and SwiftPM
//    uses it as a binary target instead of the C shim and `-L` flags, for any
//    platform the framework has a slice for.
import Foundation
import PackageDescription

let environment = ProcessInfo.processInfo.environment

let libraryDirectory =
    environment["SYMVAULT_FFI_LIB_DIR"]
    ?? Context.packageDirectory + "/../../../target/ffi"

// SwiftPM wants a binary target path relative to the package root, but the
// build output lives outside the checkout; express the absolute path as ../..
func relativePath(_ path: String, from base: String) -> String {
    guard path.hasPrefix("/") else { return path }
    let target = URL(fileURLWithPath: path).standardized.pathComponents
    let origin = URL(fileURLWithPath: base).standardized.pathComponents
    var common = 0
    while common < min(target.count, origin.count), target[common] == origin[common] { common += 1 }
    let up = Array(repeating: "..", count: origin.count - common)
    return (up + target[common...]).joined(separator: "/")
}

let xcframeworkPath = environment["SYMVAULT_FFI_XCFRAMEWORK"].map {
    relativePath($0, from: Context.packageDirectory)
}

// libiconv is a system library on macOS and iOS; the Rust standard library
// pulls it in. The static library and the XCFramework both need it.
var linkerSettings: [LinkerSetting] = [.linkedLibrary("iconv")]
let cTarget: Target
if let xcframeworkPath {
    cTarget = .binaryTarget(name: "CSymvaultFFI", path: xcframeworkPath)
} else {
    cTarget = .target(name: "CSymvaultFFI", path: "Sources/CSymvaultFFI")
    linkerSettings += [
        .unsafeFlags(["-L", libraryDirectory]),
        .linkedLibrary("symvault_ffi"),
    ]
}

let package = Package(
    name: "SymvaultFFI",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "SymvaultFFI", targets: ["SymvaultFFI"])
    ],
    targets: [
        cTarget,
        .target(
            name: "SymvaultFFI",
            dependencies: ["CSymvaultFFI"],
            path: "Sources/SymvaultFFI",
            linkerSettings: linkerSettings
        ),
        .testTarget(
            name: "SymvaultFFITests",
            dependencies: ["SymvaultFFI"],
            path: "Tests/SymvaultFFITests"
        ),
    ]
)
