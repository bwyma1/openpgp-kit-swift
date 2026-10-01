import Foundation

/// Transport-independent handle to a smartcard.
///
/// Apple platforms back this with CryptoTokenKit's `TKSmartCard`; Linux backs it
/// with a PC/SC connection (see ``PCSCSmartCard``). Protocol logic in the
/// `INS/` layer only ever calls ``transmit(_:)``, so the two transports are
/// drop-in interchangeable.
public protocol SmartCardTransport: Sendable {
	/// `true` when a card is present and usable.
	var isValid: Bool { get }
	/// Opens the card session (no-op for transports where the connection itself is the session).
	func beginSession() async throws
	/// Transmits an APDU and returns the raw card response, including status words.
	func transmit(_ data: Data) async throws -> Data
}

/// The smartcard handle type used throughout the package's public API.
public typealias SmartCard = any SmartCardTransport

#if canImport(CryptoTokenKit)
import CryptoTokenKit

/// CryptoTokenKit-backed transport.
///
/// `TKSmartCard` cannot conform to ``SmartCardTransport`` directly because its
/// `beginSession()` returns a `Bool` (whether the session started); this wrapper
/// adapts it and surfaces a failed session as ``OpenPGPError/failedToStartOpenPGP``.
/// `@unchecked Sendable` because `TKSmartCard` is a non-Sendable ObjC class that
/// is used single-threaded per connection, matching the pre-existing actor usage.
public struct AppleSmartCard: SmartCardTransport, @unchecked Sendable {
	private let card: TKSmartCard

	public init(_ card: TKSmartCard) {
		self.card = card
	}

	public var isValid: Bool {
		card.isValid
	}

	public func beginSession() async throws {
		let started = try await card.beginSession()
		guard started else {
			throw OpenPGPError.failedToStartOpenPGP
		}
	}

	public func transmit(_ data: Data) async throws -> Data {
		try await card.transmit(data)
	}
}

#endif

/// Sentinel transport used before a card has been connected.
///
/// This replaces the old "empty card" default on Apple platforms and keeps
/// pre-connection misuse from being silently misrouted: any operation throws
/// ``OpenPGPError/noYubikeyDetected``.
public struct UnconnectedSmartCard: SmartCardTransport {
	public var isValid: Bool { false }

	public init() {}

	public func beginSession() async throws {
		throw OpenPGPError.noYubikeyDetected
	}

	public func transmit(_ data: Data) async throws -> Data {
		throw OpenPGPError.noYubikeyDetected
	}
}
