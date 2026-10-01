#if os(Linux)
import Dispatch
import Foundation
import cPCSC

/// Raw PC/SC result codes used by this wrapper (subset of the PC/SC v2 spec).
/// Stored as `UInt32` because the error values are > `Int32.max`; compare with
/// `UInt32(bitPattern:)`.
enum PCSCResult {
	static let success: UInt32 = 0
	static let invalidHandle: UInt32 = 0x8010_0003
	static let noSmartcard: UInt32 = 0x8010_000C
	static let commDataLost: UInt32 = 0x8010_0016
	static let readerUnavailable: UInt32 = 0x8010_0017
	static let noService: UInt32 = 0x8010_001D
	static let noReaders: UInt32 = 0x8010_002E
	static let removedCard: UInt32 = 0x8010_0069
}

/// Maps a raw PC/SC result code to a domain error.
func mapPCSCError(_ rc: Int32) -> Error {
	switch UInt32(bitPattern: rc) {
	case PCSCResult.noSmartcard, PCSCResult.removedCard, PCSCResult.noReaders,
		 PCSCResult.readerUnavailable, PCSCResult.commDataLost, PCSCResult.noService:
		return OpenPGPError.noYubikeyDetected
	default:
		return OpenPGPError.cardCreationFailed
	}
}

/// Process-wide PC/SC resource-manager context, created lazily on first access.
final class PCSCContext: @unchecked Sendable {
	static let shared = PCSCContext()

	private let lock = NSLock()
	private var handle: UInt = 0

	private init() {}

	func acquire() throws -> UInt {
		lock.lock()
		defer { lock.unlock() }
		if handle == 0 {
			var ctx: UInt = 0
			let rc = cpcsc_context_create(&ctx)
			guard rc == Int32(PCSCResult.success) else {
				throw mapPCSCError(rc)
			}
			handle = ctx
		}
		return handle
	}

	deinit {
		if handle != 0 {
			_ = cpcsc_context_release(handle)
		}
	}
}

/// PC/SC-backed smartcard handle used on Linux (via `pcscd` + `libpcsclite`).
/// Functionally equivalent to the CryptoTokenKit `TKSmartCard` path on Apple.
public final class PCSCSmartCard: SmartCardTransport {
	private static let ioQueue = DispatchQueue(label: "openpgp.kit.pcsc.io")

	private let handle: UInt
	private let activeProtocol: UInt32

	public init(readerName: String) throws {
		let context = try PCSCContext.shared.acquire()
		var card: UInt = 0
		var protocolID: UInt32 = 0
		let rc = readerName.withCString { namePointer in
			cpcsc_connect(context, namePointer, &card, &protocolID)
		}
		guard rc == Int32(PCSCResult.success) else {
			throw mapPCSCError(rc)
		}
		self.handle = card
		self.activeProtocol = protocolID
	}

	deinit {
		_ = cpcsc_disconnect(handle)
	}

	public var isValid: Bool {
		cpcsc_status(handle) == Int32(PCSCResult.success)
	}

	public func beginSession() async throws {
		// PC/SC has no separate session concept: SCardConnect already established it.
	}

	public func transmit(_ data: Data) async throws -> Data {
		try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
			Self.ioQueue.async {
				let apdu = [UInt8](data)
				var response = [UInt8](repeating: 0, count: 4096)
				var responseSize = UInt32(response.count)
				let rc = apdu.withUnsafeBufferPointer { apduPointer in
					response.withUnsafeMutableBufferPointer { responsePointer in
						cpcsc_transmit(self.handle, apduPointer.baseAddress, UInt32(apduPointer.count),
									   responsePointer.baseAddress, &responseSize, self.activeProtocol)
					}
				}
				guard rc == Int32(PCSCResult.success) else {
					continuation.resume(throwing: mapPCSCError(rc))
					return
				}
				continuation.resume(returning: Data(response[0..<Int(responseSize)]))
			}
		}
	}
}

/// Discovers PC/SC readers; the Linux counterpart of `TKSmartCardSlotManager`.
public enum PCSCSmartCardLocator {
	/// Lists reader names visible to the system PC/SC service.
	public static func listReaders() throws -> [String] {
		let context = try PCSCContext.shared.acquire()
		var size: UInt32 = 0
		var rc = cpcsc_list_readers(context, nil, &size)
		if rc == Int32(PCSCResult.noReaders) {
			return []
		}
		guard rc == Int32(PCSCResult.success) else {
			throw mapPCSCError(rc)
		}
		var buffer = [CChar](repeating: 0, count: Int(size) + 2)
		var bufferSize = UInt32(buffer.count)
		rc = cpcsc_list_readers(context, &buffer, &bufferSize)
		guard rc == Int32(PCSCResult.success) else {
			throw mapPCSCError(rc)
		}
		return Self.parseMultiString(buffer)
	}

	/// The reader most likely to hold a YubiKey, or the only available reader;
	/// returns nil when no readers are available.
	public static func preferredReader() throws -> String? {
		let readers = try listReaders()
		guard !readers.isEmpty else { return nil }
		return readers.first(where: {
			$0.localizedCaseInsensitiveContains("yubikey") || $0.localizedCaseInsensitiveContains("yubico")
		}) ?? readers[0]
	}

	private static func parseMultiString(_ buffer: [CChar]) -> [String] {
		var readers: [String] = []
		var index = 0
		while index < buffer.count {
			var end = index
			while end < buffer.count && buffer[end] != 0 {
				end += 1
			}
			if end == index {
				break // empty entry marks the end of the multi-string
			}
			readers.append(buffer[index..<end].withUnsafeBufferPointer { String(cString: $0.baseAddress!) })
			index = end + 1
		}
		return readers
	}
}

#endif
