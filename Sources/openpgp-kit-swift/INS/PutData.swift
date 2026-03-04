import CryptoTokenKit
import Foundation

/// Source: [https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf] Page 61
/// PUT DATA command:
/// - INS: 0xDA/DB
///
/// Access Condition: Depends on data.
///
/// With this command DOs can be written to the card. The Tag is given in P1/P2 (e. g. 5F50 for URL or 005B for Name).
/// For put data on enything in the Extended header list, use 0xDB along with p1=0x3F, p2=0xFF.
///
/// Returns a Bool indicating whether or not the data was written.
extension OpenPGPConnection {
	public func putData(on card:TKSmartCard, extendedHeaderList:Bool = false, P1:UInt8, P2:UInt8, lcData:Data?, le:[UInt8]?) async throws -> Bool {
		let apdu = APDU(cla: 0x00, ins: extendedHeaderList ? 0xDB : 0xDA, p1: P1, p2: P2, data: lcData, le: le)
		
		let response = try await card.transmit(apdu.serialize())
		guard response.suffix(2) == Data([0x90, 0x00]) else { return false }
		return true
	}
}
