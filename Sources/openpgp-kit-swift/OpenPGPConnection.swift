import Foundation
#if canImport(CryptoTokenKit)
import CryptoTokenKit
#endif
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

public actor OpenPGPConnection {
	let logger:Logger
	private var card: SmartCard = UnconnectedSmartCard()
	public var isConnected:Bool { card.isValid }
	
	/// Initializer waits until there is a Yubikey connected to try and start the connection.
	public init(logLevel:Logger.Level) {
		var makeLogger = Logger(label: "\(String(describing:Self.self))")
		makeLogger.logLevel = logLevel
		self.logger = makeLogger
	}
	
	/// Throws if no yubikey is connected or a card is not found.
	public func connectToYubikey() async throws {
#if canImport(CryptoTokenKit)
		let manager = TKSmartCardSlotManager()

		logger.trace("Attempting to find yubikey...")
		guard let keyName = manager.slotNames.first else {
			throw OpenPGPError.noYubikeyDetected
		}
		logger.trace("> Found yubikey: \(keyName)")
		guard let slot = await manager.getSlot(withName: keyName) else {
			throw OpenPGPError.slotCreationFailed
		}
		guard let card = slot.makeSmartCard() else {
			throw OpenPGPError.cardCreationFailed
		}
		let wrappedCard = AppleSmartCard(card)
		self.card = wrappedCard
		try await wrappedCard.beginSession()
#else
		guard let readerName = try PCSCSmartCardLocator.preferredReader() else {
			logger.warning("No smartcard reader detected. Is pcscd running?")
			throw OpenPGPError.noYubikeyDetected
		}
		logger.trace("> Found yubikey: \(readerName)")
		self.card = try PCSCSmartCard(readerName: readerName)
		try await card.beginSession()
#endif
	}
	
	/// Waits until a yubikey is connected and a the card is found.
	/// The function ends once the connection is made.
	public func waitForYubikey(retryTime: Duration) async throws {
#if canImport(CryptoTokenKit)
		let manager = TKSmartCardSlotManager()
		while true {
			logger.trace("Attempting to find yubikey...")
			guard manager.slotNames.count > 0 else {
				try? await Task.sleep(for: retryTime)
				continue
			}
			guard let keyName = manager.slotNames.first else {
				try? await Task.sleep(for: retryTime)
				continue
			}
			logger.trace("> Found yubikey: \(keyName)")
			guard let slot = await manager.getSlot(withName: keyName) else {
				throw OpenPGPError.slotCreationFailed
			}
			guard let card = slot.makeSmartCard() else {
				try? await Task.sleep(for: retryTime)
				continue
			}
			let wrappedCard = AppleSmartCard(card)
			self.card = wrappedCard
			try await wrappedCard.beginSession()
			break
		}
#else
		while true {
			if let readerName = try? PCSCSmartCardLocator.preferredReader() {
				logger.trace("> Found yubikey: \(readerName)")
				self.card = try PCSCSmartCard(readerName: readerName)
				try await card.beginSession()
				break
			}
			try? await Task.sleep(for: retryTime)
		}
#endif
	}
	
	/// Called to actually open the OpenPGP application on the yubikey.
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
		do {
			let result = try await verify(on: card, pwType: pwType, action: .startVerify, password: password)
			if result {
				logger.info("Successfully opened verify access for password type \(pwType)")
			} else {
				logger.warning("Failed to open verify access for password type \(pwType)")
				throw OpenPGPError.failedToOpenVerifyAccess
			}
		} catch let error as NSError where error.domain == "CryptoTokenKit" && error.code == -7 {
			throw OpenPGPError.noYubikeyDetected
		}
	}
	
	public func closeVerifyAccess(pwType:VerifyPWType) async throws {
		logger.debug("Attempting to close verify access for password type \(pwType)")
		do {
			let result = try await verify(on: card, pwType: pwType, action: .stopVerify, password: nil)
			if result {
				logger.info("Successfully closed verify access for password type \(pwType)")
			} else {
				logger.warning("Failed to close verify access for password type \(pwType)")
				throw OpenPGPError.failedToCloseVerifyAccess
			}
		} catch let error as NSError where error.domain == "CryptoTokenKit" && error.code == -7 {
			throw OpenPGPError.noYubikeyDetected
		}
	}
}

//MARK: - PUT DATA Functions
extension OpenPGPConnection {
	/// Requires PW3
	private func putFingerprintAndTime(publicKey:PublicKey) async throws {
		logger.debug("Attempting to put fingerprint")
		do {
			var hasher = RAW_sha1.Hasher()
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
		} catch let error as NSError where error.domain == "CryptoTokenKit" && error.code == -7 {
			throw OpenPGPError.noYubikeyDetected
		}
	}
	
	/// Requires PW3
	public func putName(name:String) async throws {
		logger.debug("Attempting to put name")
		do {
			let result = try await putData(on: card, P1: 0x00, P2: 0x5B, lcData: name.data(using: .utf8)!, le: nil)
			if result {
				logger.info("Successfully put name")
			} else {
				logger.warning("Failed to put name")
				throw OpenPGPError.failedToPutData
			}
		} catch let error as NSError where error.domain == "CryptoTokenKit" && error.code == -7 {
			throw OpenPGPError.noYubikeyDetected
		}
	}
	
	/// Requires PW3
	public func putLoginInfo(info:String) async throws {
		logger.debug("Attempting to put login information")
		do {
			let result = try await putData(on: card, P1: 0x00, P2: 0x5E, lcData: info.data(using: .utf8)!, le: nil)
			if result {
				logger.info("Successfully put login information")
			} else {
				logger.warning("Failed to put login information")
				throw OpenPGPError.failedToPutData
			}
		} catch let error as NSError where error.domain == "CryptoTokenKit" && error.code == -7 {
			throw OpenPGPError.noYubikeyDetected
		}
	}
}

//MARK: - GET DATA Functions
extension OpenPGPConnection {
	public func getName() async throws -> String {
		logger.debug("Attempting to get name")
		do {
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
		} catch let error as NSError where error.domain == "CryptoTokenKit" && error.code == -7 {
			throw OpenPGPError.noYubikeyDetected
		}
	}
	
	public func getLoginInfo() async throws -> String {
		logger.debug("Attempting to get login info")
		do {
			let result = try await getData(on: card, P1: 0x00, P2: 0x5E, lcData: nil, le: nil)
			let string = String(data: result, encoding: .utf8)
			guard let string = string else {
				logger.warning("Failed to get login info")
				throw OpenPGPError.failedToGetData
			}
			logger.info("Successfully get login info")
			return string
		} catch let error as NSError where error.domain == "CryptoTokenKit" && error.code == -7 {
			throw OpenPGPError.noYubikeyDetected
		}
	}
}

//MARK: - Managing Keys
extension OpenPGPConnection {
	public func setEd25519Key(privateKey: MemoryGuarded<RAW_ed25519.PrivateKey>, publicKey:PublicKey) async throws {
		logger.debug("Attempting to set Ed25519 key")
		do {
			let data = privateKey.RAW_access_immutable(UnsafeRawBufferPointer.self) { ptr in
				return publicKey.RAW_access_immutable(UnsafeRawBufferPointer.self) { pubPtr in
					let extHeaderList: [UInt8] = [0xB6, 0x00, 0x7F, 0x48, 0x02]		// 7F48 contains the bare 92 DO header (2 bytes)
					let privateTLV: [UInt8] = [0x92, 0x20]		// signing private key DO header; ed25519 seed is 32 bytes
					let suffixTLV: [UInt8] = [0x5F, 0x48, 0x20]	// 5F48 marker: 32 bytes of key material follow
					let keyMaterial = Array(ptr.prefix(32))		// rawdog 64-byte key is sk||pk; card wants the 32-byte seed
					var finalTLV: [UInt8] = [0x4D, UInt8(extHeaderList.count + privateTLV.count + suffixTLV.count + keyMaterial.count)]
					finalTLV.append(contentsOf: extHeaderList)
					finalTLV.append(contentsOf: privateTLV)
					finalTLV.append(contentsOf: suffixTLV)
					finalTLV.append(contentsOf: keyMaterial)
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
		} catch let error as NSError where error.domain == "CryptoTokenKit" && error.code == -7 {
			throw OpenPGPError.noYubikeyDetected
		}
	}
	
	/// Generates a new key pair on the yubikey.
	/// Important: Needs PW3 Verification (reset password)
	public func generateKey() async throws -> PublicKey {
		logger.debug("Attempting to generate new key pair")
		do {
			let keys = try await generateAsymmetricKeyPair(on: card, action: .generate, crt: .digitalSignature)
			guard let keys = keys, keys.count >= 1 else {
				logger.warning("Failed to generate new key pair")
				throw OpenPGPError.failedToGenerateKeyPair
			}
			logger.info("Successfully generated new key pair")
			
			try await putFingerprintAndTime(publicKey: keys[0])
			return keys[0]
		} catch let error as NSError where error.domain == "CryptoTokenKit" && error.code == -7 {
			throw OpenPGPError.noYubikeyDetected
		}
	}
	
	public func getPublicKeys() async throws -> [PublicKey] {
		logger.debug("Attempting to read public key")
		do {
			let keys = try await generateAsymmetricKeyPair(on: card, action: .readPublicKey, crt: .digitalSignature)
			guard let keys = keys else {
				logger.warning("Failed to read public key")
				throw OpenPGPError.failedToReadPublicKey
			}
			logger.info("Successfully read public key")
			return keys
		} catch let error as NSError where error.domain == "CryptoTokenKit" && error.code == -7 {
			throw OpenPGPError.noYubikeyDetected
		}
	}
	
	/// Requires PW3
	public func setSigningFuntionEd25519() async throws {
		logger.debug("Attempting to set signing function to ed25519")
		do {
			let ed25519FunctionEncoding = Data([0x16, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01])
			let result = try await putData(on: card, P1: 0x00, P2: 0xC1, lcData: ed25519FunctionEncoding, le: nil)
			if result {
				logger.info("Successfully set signing function to ed25519")
			} else {
				logger.warning("Failed to set signing function to ed25519")
				throw OpenPGPError.failedToPutData
			}
		} catch let error as NSError where error.domain == "CryptoTokenKit" && error.code == -7 {
			throw OpenPGPError.noYubikeyDetected
		}
	}
}

//MARK: - Signing
extension OpenPGPConnection {
	/// Requires PW1
	public func computeDitigalSignature<DataType:RAW_accessible>(hashedData: DataType) async throws -> Data {
		logger.debug("Attempting to compute digital signature")
		do {
			return try await computeDigitalSignature(on: card, hashedData: hashedData)
		} catch let error as NSError where error.domain == "CryptoTokenKit" && error.code == -7 {
			throw OpenPGPError.noYubikeyDetected
		}
	}
}
