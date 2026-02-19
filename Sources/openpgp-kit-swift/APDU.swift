import Foundation

/// OpenPGP Application Protocol Data Unit
///
/// CLA: Class Byte. Identifies the class of the instruction. (Smart Cards usually 0x00 or 0x80)
/// INS: Instrruction Byte: Specifies the command to perform. (SELECT, GET DATA, PUT DATA, ...)
/// P1 & P2: Parameter Bytes. Provide instruction specific parameters.
/// Lc: Length of the command data passed with the APDU.
/// Data: Command Data. Contains the necessary data needed for the command.
/// Le: Expected length of the response. Indicates how many bytes the response should be.
struct APDU {
	let cla: UInt8
	let ins: UInt8
	let p1: UInt8
	let p2: UInt8
	let data: Data?
	let le: [UInt8]?

	func serialize() -> Data {
		var d = Data([cla, ins, p1, p2])
		if let data = data {
			d.append(UInt8(data.count))
			d.append(data)
		}
		d.append(contentsOf: le ?? [])
		return d
	}
}
