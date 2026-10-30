// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "PhoneKeyCore",
    platforms: [.iOS(.v15), .macOS(.v12)],
    products: [
        .library(name: "PhoneKeyCore", targets: ["PhoneKeyCore"]),
    ],
    targets: [
        .target(name: "PhoneKeyCore"),
        .testTarget(name: "PhoneKeyCoreTests", dependencies: ["PhoneKeyCore"]),
    ]
)
