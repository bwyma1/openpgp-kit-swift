import CryptoTokenKit
import Foundation
import RAW

/// Source: [https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf] Page 63-64
/// GET DATA command:
/// - INS: 0x2A
/// - P1: 0x9E
/// - P2: 0x9A
///
/// Access Condition: Verify of PW1 no. 0x81
///
/// Signature key as well as signature algorithm and the related Digital-Signature-Input formats are implicitly selected.
/// The command always use the SIG-key (Key-Ref 1).
///
/// Returns the 64-byte hash from signing the message on status success (9000), else throws corresponding error.
extension OpenPGPConnection {
	public func computeDigitalSignature<DataType:RAW_accessible>(on card:TKSmartCard, hashedData:DataType) async throws -> Data {
		var data = Data()
		hashedData.RAW_access_immutable(UnsafeRawBufferPointer.self) { ptr in
			data.append(contentsOf: ptr)
		}
		let apdu = APDU(cla: 0x00, ins: 0x2A, p1: 0x9E, p2: 0x9A, data: data, le: nil)
		let response = try await card.transmit(apdu.serialize())
		guard response.suffix(2) == Data([0x90, 0x00]) else {
			logger.warning("COMPUTE DIGITAL SIGNATURE failed: card returned \(response.map { String(format: "%02X", $0) }.joined(separator: " "))")
			throw OpenPGPError.failedToSignData
		}
		return response.dropLast(2)
	}
}
