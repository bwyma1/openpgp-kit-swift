// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "openpgp-kit-swift",
	platforms: [
		.macOS(.v15)
	],
	products: [
		// Products define the executables and libraries a package produces, making them visible to other packages.
		.executable(name:"openpgp-tests", targets:["openpgp-tests"]),
		.library(name: "openpgp-kit", targets: ["openpgp-kit-swift"]),
	],
	dependencies:[
		.package(url:"https://github.com/tannerdsilva/rawdog.git", "21.0.0"..<"22.0.0"),
		.package(url: "https://github.com/apple/swift-log.git", from: "1.0.0"),
	],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "openpgp-kit-swift",
			dependencies:[
				.product(name:"Logging", package:"swift-log"),
				.product(name:"RAW", package:"rawdog"),
				.product(name:"RAW_dh25519", package:"rawdog"),
				.product(name:"RAW_sha1", package:"rawdog"),
				.product(name:"RAW_sha256", package:"rawdog"),
				.product(name:"RAW_base64", package:"rawdog"),
				.product(name:"RAW_ed25519", package:"rawdog"),
			],
			exclude: ["SmartCard.entitlements"]
        ),
        .executableTarget(
            name: "openpgp-tests",
            dependencies: ["openpgp-kit-swift"]
        ),
    ]
)
