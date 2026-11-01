// swift-tools-version:5.9
//
// Swift binding and integration test for crates/symvault-ffi (FFI-001).
//
// Build the Rust static library first (`make ffi-differential` does):
//
//     cargo build -p symvault-ffi --profile ffi --locked
//
// then point SYMVAULT_FFI_LIB_DIR at the directory holding libsymvault_ffi.a
// (default: <repo>/target/ffi, i.e. CARGO_TARGET_DIR=target).
import Foundation
import PackageDescription

let libraryDirectory =
    ProcessInfo.processInfo.environment["SYMVAULT_FFI_LIB_DIR"]
    ?? Context.packageDirectory + "/../../../target/ffi"

let package = Package(
    name: "SymvaultFFI",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "SymvaultFFI", targets: ["SymvaultFFI"])
    ],
    targets: [
        .target(name: "CSymvaultFFI", path: "Sources/CSymvaultFFI"),
        .target(
            name: "SymvaultFFI",
            dependencies: ["CSymvaultFFI"],
            path: "Sources/SymvaultFFI",
            linkerSettings: [
                .unsafeFlags(["-L", libraryDirectory]),
                .linkedLibrary("symvault_ffi"),
                .linkedLibrary("iconv"),
            ]
        ),
        .testTarget(
            name: "SymvaultFFITests",
            dependencies: ["SymvaultFFI"],
            path: "Tests/SymvaultFFITests"
        ),
    ]
)
