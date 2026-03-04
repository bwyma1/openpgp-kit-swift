import CryptoTokenKit
import Foundation

/// Source: [https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf] Page 58
/// GET DATA command:
/// - INS: 0xCA/CB
///
/// Access Condition: Depends on data.
///
/// With this command DOs can be read from the card. The Tag (simple or constructed) is given in P1/P2.
/// For simple DOs only the value is in the response field (e. g. 5F50 = URL returns a byte string representing the URL without leading Tag/Length).
/// For constructed DOs all values (child DOs) returned are encapsulated with their Tag/Length (e. g. 0065 = Cardholder Related Data returns the
/// concatenation of the following DOs (L = Length): 5B L Name 5F2D L Language Preferences 5F35 L Sex).
///
/// Returns the data response on status success (9000), else throws corresponging error.
extension OpenPGPConnection {
	public func getData(on card:TKSmartCard, P1:UInt8, P2:UInt8, lcData:Data?, le:[UInt8]?) async throws -> Data {
		let apdu = APDU(cla: 0x00, ins: 0xCA, p1: P1, p2: P2, data: lcData, le: le)
		
		let response = try await card.transmit(apdu.serialize())
		guard response.suffix(2) == Data([0x90, 0x00]) else {
			throw OpenPGPError.failedToGetData
		}
		return response.dropLast(2)
	}
}
