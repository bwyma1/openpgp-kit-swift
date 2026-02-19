import CryptoTokenKit
import Foundation
import Logging
import RAW
import RAW_sha1
import RAW_ed25519
import RAW_dh25519

public enum OpenPGPError: Error {
	case noYubikeyDetected
	case slotCreationFailed
	case cardCreationFailed
	
	case failedToStartOpenPGP
	
	case failedToOpenVerifyAccess
	case failedToCloseVerifyAccess
	
	case failedToGenerateKeyPair
	case failedToReadPublicKey
	
	case failedToSignData
	
	case failedToPutData
	case failedToGetData
	case failedToGetName
}

@RAW_staticbuff(bytes: 20)
fileprivate struct Fingerprint:Sendable, Hashable { }

public class OpenPGPConnection {
	private let logger:Logger
	let card: TKSmartCard
	
	public init(logLevel:Logger.Level) async throws {
		var makeLogger = Logger(label: "\(String(describing:Self.self))")
		makeLogger.logLevel = logLevel
		self.logger = makeLogger
		
		let manager = TKSmartCardSlotManager()
		guard let keyName = manager.slotNames.first else {
			throw OpenPGPError.noYubikeyDetected
		}
		print("Found key: \(keyName)")
		guard let slot = await manager.getSlot(withName: keyName) else {
			throw OpenPGPError.slotCreationFailed
		}
		guard let card = slot.makeSmartCard() else {
			throw OpenPGPError.cardCreationFailed
		}
		self.card = card
		try await card.beginSession()
	}
	
	deinit {
		logger.debug("De-initialising OpenPGPConnection")
		card.endSession()
	}
	
	public func startOpenPGP() async throws {
		logger.debug("Attempting to select OpenPGP Application on Yubikey")
		let result = try await selectOpenPGP(on: card)
		if result {
			logger.info("Successfully selected OpenPGP Application on Yubikey")
		} else {
			logger.warning("Faield to select OpenPGP Application on Yubikey. Does the Yubikey have the correct firmware?")
			throw OpenPGPError.failedToStartOpenPGP
		}
	}
}

//MARK: - Verifying Access
extension OpenPGPConnection {
	// Need to add more detailed failures (especially since incorrect passwords only get 3 guesses)
	public func openVerifyAccess(pwType:VerifyPWType, password:Data) async throws {
		logger.debug("Attempting to open verify access for password type \(pwType)")
		let result = try await verify(on: card, pwType: pwType, action: .startVerify, password: password)
		if result {
			logger.info("Successfully opened verify access for password type \(pwType)")
		} else {
			logger.warning("Failed to open verify access for password type \(pwType)")
			throw OpenPGPError.failedToOpenVerifyAccess
		}
	}
	
	public func closeVerifyAccess(pwType:VerifyPWType) async throws {
		logger.debug("Attempting to close verify access for password type \(pwType)")
		let result = try await verify(on: card, pwType: pwType, action: .stopVerify, password: nil)
		if result {
			logger.info("Successfully closed verify access for password type \(pwType)")
		} else {
			logger.warning("Failed to close verify access for password type \(pwType)")
			throw OpenPGPError.failedToCloseVerifyAccess
		}
	}
}

//MARK: - PUT DATA Functions
extension OpenPGPConnection {
	/// Requires PW3
	private func putFingerprintAndTime(publicKey:PublicKey) async throws {
		logger.debug("Attempting to put fingerprint")
		var hasher = RAW_sha1.Hasher<Fingerprint>()
		try hasher.update(publicKey)
		var data = Data(count: 20)
		try data.withUnsafeMutableBytes { ptr in
			try hasher.finish(into: ptr.baseAddress!)
		}
		_ = try await putData(on: card, P1: 0x00, P2: 0xC7, lcData: nil, le: nil)
		let fingerprintResult = try await putData(on: card, P1: 0x00, P2: 0xC7, lcData: data, le: nil)
		
		let now = UInt32(Date().timeIntervalSince1970)
		var bigEndianTime = now.bigEndian
		let timeData = Data(bytes: &bigEndianTime, count: 4)
		_ = try await putData(on: card, P1: 0x00, P2: 0xCE, lcData: nil, le: nil)
		let timeResult = try await putData(on: card, P1: 0x00, P2: 0xCE, lcData: timeData, le: nil)
		
		if fingerprintResult && timeResult {
			logger.info("Successfully put fingerprint")
		} else {
			logger.warning("Failed to put fingerprint")
			throw OpenPGPError.failedToPutData
		}
	}
	
	/// Requires PW3
	public func putName(name:String) async throws {
		logger.debug("Attempting to put name")
		let result = try await putData(on: card, P1: 0x00, P2: 0x5B, lcData: name.data(using: .utf8)!, le: nil)
		if result {
			logger.info("Successfully put name")
		} else {
			logger.warning("Failed to put name")
			throw OpenPGPError.failedToPutData
		}
	}
	
	/// Requires PW3
	public func putLoginInfo(info:String) async throws {
		logger.debug("Attempting to put login information")
		let result = try await putData(on: card, P1: 0x00, P2: 0x5E, lcData: info.data(using: .utf8)!, le: nil)
		if result {
			logger.info("Successfully put login information")
		} else {
			logger.warning("Failed to put login information")
			throw OpenPGPError.failedToPutData
		}
	}
}

//MARK: - GET DATA Functions
extension OpenPGPConnection {
	public func getName() async throws -> String {
		logger.debug("Attempting to get name")
		var result = try await getData(on: card, P1: 0x00, P2: 0x65, lcData: nil, le: nil)
		result = result.dropFirst(2)
		guard result.count >= 2, result.prefix(1) == Data([0x5B]) else {
			logger.warning("Failed to get name")
			throw OpenPGPError.failedToGetName
		}
		let length = Int([UInt8](result)[1])
		guard result.count >= 2 + length, let string = String(data: result.subdata(in: 3 ..< 4 + length), encoding: .utf8) else {
			logger.warning("Failed to get name")
			throw OpenPGPError.failedToGetName
		}
		logger.info("Successfully get name")
		return string
	}
	
	public func getLoginInfo() async throws -> String {
		logger.debug("Attempting to get login info")
		let result = try await getData(on: card, P1: 0x00, P2: 0x5E, lcData: nil, le: nil)
		let string = String(data: result, encoding: .utf8)
		guard let string = string else {
			logger.warning("Failed to get login info")
			throw OpenPGPError.failedToGetData
		}
		logger.info("Successfully get login info")
		return string
	}
}

//MARK: - Managing Keys
extension OpenPGPConnection {
	public func setEd25519Key(privateKey: MemoryGuarded<Ed25519.PrivateKey>, publicKey:PublicKey) async throws {
		logger.debug("Attempting to set Ed25519 key")
		let data = privateKey.RAW_access { ptr in
			return publicKey.RAW_access { pubPtr in
				var privateTLV: [UInt8] = [0x92, 0x20]
				var publicTLV: [UInt8] = [0x99, 0x20]
				privateTLV.append(contentsOf: Array(ptr.prefix(32)))
				publicTLV.append(contentsOf: Array(pubPtr))
				var innerTLV = privateTLV + publicTLV
				var newTLV: [UInt8] = [0xB6, 0x00, 0x7F, 0x48, UInt8(innerTLV.count)]
				newTLV.append(contentsOf: innerTLV)
				var finalTLV: [UInt8] = [0x4D, UInt8(newTLV.count)]
				finalTLV.append(contentsOf: newTLV)
				return Data(finalTLV)
			}
		}
		let result = try await putData(on: card, extendedHeaderList: true, P1: 0x3F, P2: 0xFF, lcData: data, le: nil)
		try await putFingerprintAndTime(publicKey: publicKey)
		if result {
			logger.info("Successfully set Ed25519 key")
		} else {
			logger.warning("Failed to set Ed25519 key")
			throw OpenPGPError.failedToPutData
		}
	}
	
	/// Generates a new key pair on the yubikey.
	/// Important: Needs PW3 Verification (reset password)
	public func generateKey() async throws -> PublicKey {
		logger.debug("Attempting to generate new key pair")
		let keys = try await generateAsymmetricKeyPair(on: card, action: .generate, crt: .digitalSignature)
		guard let keys = keys, keys.count >= 1 else {
			logger.warning("Failed to generate new key pair")
			throw OpenPGPError.failedToGenerateKeyPair
		}
		logger.info("Successfully generated new key pair")
		
		try await putFingerprintAndTime(publicKey: keys[0])
		return keys[0]
	}
	
	public func getPublicKeys() async throws -> [PublicKey] {
		logger.debug("Attempting to read public key")
		let keys = try await generateAsymmetricKeyPair(on: card, action: .readPublicKey, crt: .digitalSignature)
		guard let keys = keys else {
			logger.warning("Failed to read public key")
			throw OpenPGPError.failedToReadPublicKey
		}
		logger.info("Successfully read public key")
		return keys
	}
	
	/// Requires PW3
	public func setSigningFuntionEd25519() async throws {
		logger.debug("Attempting to set signing function to ed25519")
		let ed25519FunctionEncoding = Data([0x16, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01])
		let result = try await putData(on: card, P1: 0x00, P2: 0xC1, lcData: ed25519FunctionEncoding, le: nil)
		if result {
			logger.info("Successfully set signing function to ed25519")
		} else {
			logger.warning("Failed to set signing function to ed25519")
			throw OpenPGPError.failedToPutData
		}
	}
}

//MARK: - Signing
extension OpenPGPConnection {
	/// Requires PW1
	public func computeDitigalSignature<DataType:RAW_accessible>(hashedData: DataType) async throws -> Data {
		logger.debug("Attempting to compute digital signature")
		return try await computeDigitalSignature(on: card, hashedData: hashedData)
	}
}
