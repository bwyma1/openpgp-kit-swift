import CryptoTokenKit
import Foundation
import RAW_dh25519
import RAW_ed25519
import RAW_base64

/// Defined CRTs (Control Reference Template) for the command (generation of key pair or reading of public key) in simple and extended format with Key-Ref.
public enum KeyPairCRT {
	case digitalSignature
	case confidentiality
	case authentication
}

/// Defines the parameter actions for the generate asymmetric key pair command.
public enum KeyPairParameter {
	case generate
	case readPublicKey
}

/// Source: [https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf] Page 74
/// GENERATE ASYMMETRIC KEY PAIR command:
/// - INS: 0x47
/// - P1: 0x80 (generate), 0x81 (read public key)
///
/// Access Condition: Verify of PW3 for generating keys.
///
/// This command either initiates the generation and storing of an asymmetric key pair, i. e., a public key and a private key in the card,
/// OR returns the public key of an asymmetric key pair previously generated in the card or imported.
///
/// Returns:
/// - The public key created from the key generation.
/// - The public key(s) returned from reading the key.
/// - Nil for unsuccessful generation or fetch.
extension OpenPGPConnection {
	public func generateAsymmetricKeyPair(on card:TKSmartCard, action: KeyPairParameter, crt: KeyPairCRT) async throws -> [PublicKey]? {
		let P1: UInt8 = action == .generate ? 0x80 : 0x81
		switch crt {
			case .digitalSignature:
				let apdu = APDU(cla: 0x00, ins: 0x47, p1: P1, p2: 0x00, data: Data([0xB6, 0x00]), le: nil)
				
				let response = try await card.transmit(apdu.serialize())
				let keys = extractEd25519Keys(from: response)
				return keys
			default:
				// Don't have them all implemented yet.
				fatalError("Unsupported CRT: \(crt)")
		}
	}
}

/// Parses an APDU response and extracts Ed25519 public keys (tag 0x86 inside 7F49 container)
/// - Parameter response: The raw APDU response from the card
/// - Returns: Array of Data objects, each being a 32-byte Ed25519 public key
func extractEd25519Keys(from response: Data) -> [PublicKey]? {
	var keys: [Data] = []
	var index = 0
	
	// Ensure we have at least a 7F49 tag
	while index < response.count {
		let tag = response[index]
		
		if tag == 0x7F {
			// Check if next byte is 0x49
			guard index + 1 < response.count, response[index + 1] == 0x49 else {
				index += 1
				continue
			}
			
			index += 2 // Move past 7F49
			
			// Parse length (TLV)
			guard index < response.count else { break }
			var length = 0
			let lengthByte = response[index]
			index += 1
			
			if lengthByte & 0x80 != 0 {
				// Multi-byte length
				let numBytes = Int(lengthByte & 0x7F)
				guard index + numBytes <= response.count else { break }
				length = 0
				for i in 0..<numBytes {
					length = (length << 8) + Int(response[index + i])
				}
				index += numBytes
			} else {
				// Single-byte length
				length = Int(lengthByte)
			}
			
			let containerEnd = index + length
			guard containerEnd <= response.count else { break }
			
			// Scan inside 7F49 container
			while index < containerEnd {
				let innerTag = response[index]
				index += 1
				
				guard index < containerEnd else { break }
				
				// Parse inner length
				var innerLength = 0
				let innerLengthByte = response[index]
				index += 1
				
				if innerLengthByte & 0x80 != 0 {
					let numBytes = Int(innerLengthByte & 0x7F)
					guard index + numBytes <= containerEnd else { break }
					innerLength = 0
					for i in 0..<numBytes {
						innerLength = (innerLength << 8) + Int(response[index + i])
					}
					index += numBytes
				} else {
					innerLength = Int(innerLengthByte)
				}
				
				// Only care about Ed25519 public key (tag 0x86)
				if innerTag == 0x86 {
					guard index + innerLength <= containerEnd else { break }
					let keyData = response.subdata(in: index ..< index + innerLength)
					
					// Ed25519 keys are 32 bytes
					if keyData.count == 32 {
						keys.append(keyData)
					}
				}
				
				index += innerLength
			}
		} else {
			// Not a 7F49 tag, skip
			index += 1
		}
	}
	
	var rawKeys: [PublicKey] = []
	for key in keys {
		let pubKey = key.withUnsafeBytes { rawBuffer -> PublicKey in
			guard let baseAddress = rawBuffer.baseAddress else {
				fatalError("Data has no base address")
			}
			var ptr = baseAddress
			return PublicKey(RAW_staticbuff_seeking: &ptr)
		}
		rawKeys.append(pubKey)
	}
	guard rawKeys != [] else { return nil }
	return rawKeys
}
