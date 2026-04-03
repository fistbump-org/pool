// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "pool",
    platforms: [
        .macOS(.v13),
    ],
    dependencies: [
        .package(url: "https://github.com/fistbump-org/fbd.git"),
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.3.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.5.0"),
    ],
    targets: [
        .executableTarget(
            name: "pool",
            dependencies: [
                .product(name: "Base", package: "fbd"),
                .product(name: "ExtCrypto", package: "fbd"),
                .product(name: "Protocol", package: "fbd"),
                .product(name: "Consensus", package: "fbd"),
                .product(name: "Mining", package: "fbd"),
                .product(name: "RPC", package: "fbd"),
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Sources/pool-cli"
        ),

        .executableTarget(
            name: "miner",
            dependencies: [
                .product(name: "Base", package: "fbd"),
                .product(name: "ExtCrypto", package: "fbd"),
                .product(name: "Protocol", package: "fbd"),
                .product(name: "Consensus", package: "fbd"),
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Sources/miner"
        ),
    ]
)
