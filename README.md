# openpgp-kit-swift

A Swift package for interacting with the OpenPGP application on a YubiKey smart card, built on `CryptoTokenKit` (macOS).

## Features

- Connect and select the OpenPGP application on a connected YubiKey
- Verify access with user (PW1) and admin (PW3) passwords
- Read and write cardholder data (name, login info)
- Generate Ed25519 key pairs on the card
- Read public keys from the card
- Import an externally generated Ed25519 signing key into the card
- Set Ed25519 as the signing function
- Compute and verify digital signatures (requires PW1)

## Requirements

- macOS 15 or later
- Swift 6.2
- A YubiKey with the OpenPGP application (for runtime use)

## Installation

Add the package as a dependency in `Package.swift`:

```swift
.package(url: "https://github.com/bwyma1/openpgp-kit-swift.git", from: "0.1.0")
```

## Usage

```swift
import openpgp_kit_swift

let connection = OpenPGPConnection(logLevel: .info)
try await connection.waitForYubikey(retryTime: .seconds(1))
try await connection.startOpenPGP()

// Verify admin access, generate a key pair, and read it back
try await connection.openVerifyAccess(pwType: .admin, password: adminPassword)
let publicKey = try await connection.generateKey()
let keys = try await connection.getPublicKeys()
try await connection.closeVerifyAccess(pwType: .admin)

// Sign hashed data (requires user access)
try await connection.openVerifyAccess(pwType: .user, password: userPassword)
let signature = try await connection.computeDitigalSignature(hashedData: hashedData)
try await connection.closeVerifyAccess(pwType: .user)
```

Note: user (PW1) verification is required for signing; admin (PW3) verification is required for key generation, key import, and writing cardholder data.

## Running the tests

The `openpgp-tests` executable exercises the full flow against a physical YubiKey and must be signed with the SmartCard entitlements. Run it with:

```sh
./run.sh
```

The test expects a card with default PINs (`123456` / `12345678`) and will modify card state (generate keys, write cardholder data).
