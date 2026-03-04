import openpgp_kit_swift
import Foundation
import Logging
import RAW
import RAW_base64
import RAW_ed25519
import RAW_sha256
import RAW_dh25519

@RAW_convertible_string_type<UTF8>(backing:RAW_byte.self)
public struct EncodedString:Sendable, Equatable, Hashable, Comparable, ExpressibleByStringLiteral, CustomDebugStringConvertible {
	public var debugDescription:String {
		return String(self)
	}
}
@RAW_staticbuff(bytes: 32)
/// Testing sha256 hashed object
public struct Test32ShaHash:Sendable, Hashable, Comparable, RAW_convertible, RAW_accessible { }


@main
struct Testing {
	static func main() async throws {
		let logger = Logger(label: "OpenPGPTests")
		
		let openPGPConnection = OpenPGPConnection(logLevel: .trace)
		try await openPGPConnection.waitForYubikey(retryTime: .seconds(0.5))
		try await openPGPConnection.startOpenPGP()
		
		let data = EncodedString(stringLiteral: "Raw Data")
		var hasher = RAW_sha256.Hasher<Test32ShaHash>()
		try hasher.update(data)
		var id = Test32ShaHash(RAW_staticbuff: Test32ShaHash.RAW_staticbuff_zeroed())
		try id.RAW_access_staticbuff_mutating({ ptr in
			try hasher.finish(into: ptr)
		})
		
		//MARK: - Testing that closing verify access when it's not open doesn't crash
		try await openPGPConnection.closeVerifyAccess(pwType: .user)
		try await openPGPConnection.closeVerifyAccess(pwType: .admin)
		
		//MARK: - Testing that operations without verification don't work
		do {
			try await openPGPConnection.setSigningFuntionEd25519()
			fatalError("Verification was not open, so setting signing function should have crashed")
		} catch {}
		do {
			_ = try await openPGPConnection.generateKey()
			fatalError("Verification was not open, so adding key should have crashed")
		} catch {}
		do {
			try await openPGPConnection.putName(name: "Alice")
			fatalError("Verification was not open, so adding name should have crashed")
		} catch {}
		
		//MARK: - Testing opening verification with the wrong password
		do {
			try await openPGPConnection.openVerifyAccess(pwType: .admin, password: "000000".data(using: .utf8)!)
			fatalError("User verification should have failed")
		} catch {}
		do {
			try await openPGPConnection.openVerifyAccess(pwType: .admin, password: "00000000".data(using: .utf8)!)
			fatalError("Admin verification should have failed")
		} catch {}
		
		//MARK: - Setting signing function to Ed25519
		try await openPGPConnection.openVerifyAccess(pwType: .admin, password: "12345678".data(using: .utf8)!)
		try await openPGPConnection.setSigningFuntionEd25519()
		try await openPGPConnection.closeVerifyAccess(pwType: .admin)
		
		//MARK: - Generating a new key on the device
		try await openPGPConnection.openVerifyAccess(pwType: .admin, password: "12345678".data(using: .utf8)!)
		let generatedKey = try await openPGPConnection.generateKey()
		logger.info("Test Passed: Generated new Key ✅ \(String(RAW_base64.encode(generatedKey)))")
		try await openPGPConnection.closeVerifyAccess(pwType: .admin)
		
		//MARK: - Test putting/getting new name
		try await openPGPConnection.openVerifyAccess(pwType: .admin, password: "12345678".data(using: .utf8)!)
		try await openPGPConnection.putName(name: "Alice")
		let name = try await openPGPConnection.getName()
		guard name.contains("Alice") else { fatalError("Name was not set correctly \(name)") }
		try await openPGPConnection.closeVerifyAccess(pwType: .admin)
		
		//MARK: - Test putting/getting new login info
		try await openPGPConnection.openVerifyAccess(pwType: .admin, password: "12345678".data(using: .utf8)!)
		try await openPGPConnection.putLoginInfo(info: "Alice@gmail.com")
		let loginInfo = try await openPGPConnection.getLoginInfo()
		guard loginInfo == "Alice@gmail.com" else { fatalError("Name was not set correctly \(loginInfo)") }
		try await openPGPConnection.closeVerifyAccess(pwType: .admin)
		
		//MARK: - Testing signing/verifying process
		let key = try await openPGPConnection.getPublicKeys()[0]
		logger.info("Test Passed: Read the public key ✅ \(String(RAW_base64.encode(key)))")
		try await openPGPConnection.openVerifyAccess(pwType: .user, password: "123456".data(using: .utf8)!)
		let signature = try await openPGPConnection.computeDitigalSignature(hashedData: id)
		
		signature.withUnsafeBytes { sigPtr in
			id.RAW_access { idPtr in
				guard Ed25519.verify(signature: sigPtr.baseAddress!, publicKey: key, message: idPtr) else {
					fatalError("Test Failed: Signature with OpenPGP generated key did not verify.")
				}
				logger.info("Test Passed: Signature with OpenPGP generated key verified. ✅")
			}
		}
		
		//MARK: - Testing that signature doesn't work without verify access
		try await openPGPConnection.closeVerifyAccess(pwType: .user)
		do {
			_ = try await openPGPConnection.computeDitigalSignature(hashedData: id)
			fatalError("Test Failed: Verify Access didn't close properly.")
		} catch {
			logger.info("Test Passed: Verify Access closed properly. ✅")
		}
		
		//MARK: - Testing setting Ed25519 Key (wip)
//		try await openPGPConnection.openVerifyAccess(pwType: .admin, password: "12345678".data(using: .utf8)!)
//		let aliceStaticPrivateKey = MemoryGuarded<PrivateKey>(RAW_decode:try! RAW_base64.decode("8DFnI7tPWLl4WmuEp4T5KVuKMW6iyjRdTb3IVaDe+kI="), count:32)!
//		let (edPubKey, edPrivKey) = try Ed25519.generateKeys(secretKey: aliceStaticPrivateKey)
//		try await openPGPConnection.setEd25519Key(privateKey: edPrivKey, publicKey: edPubKey)
//		signature = try await openPGPConnection.computeDitigalSignature(hashedData: id)
//		
//		signature.withUnsafeBytes { sigPtr in
//			id.RAW_access { idPtr in
//				guard Ed25519.verify(signature: sigPtr.baseAddress!, publicKey: edPubKey, message: idPtr) else {
//					fatalError("Test Failed: Signature with custom ed25519 key did not verify.")
//				}
//				logger.info("Test Passed: Signature with custom ed25519 key verified. ✅")
//			}
//		}
//		try await openPGPConnection.closeVerifyAccess(pwType: .admin)
	}
}
