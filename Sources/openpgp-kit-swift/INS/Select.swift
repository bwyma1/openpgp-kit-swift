import Foundation

/// Source: [https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf] Page 57
/// SELECT command:
/// - INS: 0xA4
///
/// Access Condition: Always Available
///
/// With this command the OpenPGP application in the terminal selects the corresponding
/// application on the card. Only the significant bytes of the AID are presented in the command data.
/// Possible response data (FCI) don't need to be evaluated by the application.
/// A valid SELECT of the OpenPGP application sets the curConstructedDO pointer to the Virtual Root DO and adds all data objects in the application to the current template.
/// The curDO pointer is undefined, so a following GET/PUT DATA command will always reference the first occurrence of a DO.
/// The command sets all private keys (Key-Ref) to their default bindings.
///
/// Returns a Bool indicating whether or not the OpenPGP Application was successfully selected.
extension OpenPGPConnection {
	public func selectOpenPGP(on card:SmartCard) async throws -> Bool {
		let apdu = APDU(cla: 0x00, ins: 0xA4, p1: 0x04, p2: 0x00, data: Data([0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]), le: nil)
		
		let response = try await card.transmit(apdu.serialize())
		return response == Data([0x90, 0x00])
	}
}
