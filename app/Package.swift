// swift-tools-version:5.9
import PackageDescription

// The Rust core is linked as a static library built by `cargo build --release -p recovery-ffi`.
let rustLib = "\(Context.packageDirectory)/../target/release"

let package = Package(
    name: "Reline",
    defaultLocalization: "en",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "Reline", targets: ["RelineApp"]),
        .library(name: "RecoveryKit", targets: ["RecoveryKit"]),
    ],
    targets: [
        .target(
            name: "CRecoveryCore",
            path: "Sources/CRecoveryCore",
            publicHeadersPath: "include",
            linkerSettings: [
                .unsafeFlags(["-L", rustLib]),
                .linkedLibrary("recovery_ffi"),
            ]
        ),
        .target(name: "RecoveryKit", dependencies: ["CRecoveryCore"], path: "Sources/RecoveryKit"),
        .executableTarget(
            name: "RelineApp",
            dependencies: ["RecoveryKit"],
            path: "Sources/RelineApp",
            resources: [.process("Resources")]
        ),
        .testTarget(name: "RecoveryKitTests", dependencies: ["RecoveryKit"], path: "Tests/RecoveryKitTests"),
    ]
)
