#!/bin/bash
set -e

echo "Building..."
swift build

echo "Removing existing code signature..."
codesign --remove-signature .build/debug/openpgp-tests || true

echo "Re-signing with entitlements..."
codesign \
  --entitlements Sources/openpgp-kit-swift/SmartCard.entitlements \
  -s - \
  .build/debug/openpgp-tests

echo "Running..."
swift run
