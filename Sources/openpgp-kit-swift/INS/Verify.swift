import CryptoTokenKit
import Foundation

public enum VerifyPWType {
	case user
	case admin
}

public enum VerifyAction {
	case startVerify
	case stopVerify
}

/// Source: [https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf] Page 52-53
/// VERIFY command:
/// - INS: 0x20
/// - P1: 0x00 (verifying), 0xFF (addressed P2 password is set to 'not verified)
/// - P2: 0x81 (PW1), 0x82 (PW1), 0x83 (PW3)
///
/// The VERIFY command is used to check the correct password given in the command data and set an appropriate access status for the relevant password.
/// If the command is called without data, the actual access status of the addressed password is returned or the access status is set to 'not verified'.
///
/// Returns a Bool indicating the success of the command.
extension OpenPGPConnection {
	public func verify(on card:TKSmartCard, pwType:VerifyPWType, action:VerifyAction, password:Data?) async throws -> Bool {
		let P1:UInt8 = action == .startVerify ? 0x00 : 0xFF
		let P2:UInt8 = pwType == .user ? 0x81 : 0x83
		let apdu = APDU(cla: 0x00, ins: 0x20, p1: P1, p2: P2, data: password, le: nil)
		
		let response = try await card.transmit(apdu.serialize())
		guard response.suffix(2) == Data([0x90, 0x00]) else { return false }
		return true
	}
}
