import Foundation

#if canImport(CryptoTokenKit)
import CryptoTokenKit

/// The smartcard handle used throughout the package.
/// On Apple platforms this is CryptoTokenKit's `TKSmartCard`; on other platforms a
/// build-only stub is used so the package still compiles without a smartcard stack.
public typealias SmartCard = TKSmartCard

#else

/// Build-only stand-in for a smartcard handle on platforms without `CryptoTokenKit`.
///
/// The package compiles on Linux, but no card operations are possible: every
/// interaction throws ``SmartCardError/unsupportedPlatform``.
public struct SmartCard: Sendable {
	/// Errors thrown by the platform stub.
	public enum SmartCardError: Swift.Error {
		/// CryptoTokenKit is unavailable on this platform.
		case unsupportedPlatform
	}

	/// Always `false` on unsupported platforms.
	public var isValid: Bool { false }

	public init() {}

	/// Always throws ``SmartCardError/unsupportedPlatform``.
	public func beginSession() async throws {
		throw SmartCardError.unsupportedPlatform
	}

	/// Always throws ``SmartCardError/unsupportedPlatform``.
	public func transmit(_ data: Data) async throws -> Data {
		throw SmartCardError.unsupportedPlatform
	}
}

#endif
