//
//  CryptoAgentTest.swift
//  passKitTests
//

import XCTest
@testable import passKit

final class CryptoAgentTest: XCTestCase {

    var tempDir: URL!
    var keychain: KeyStore!

    override func setUp() {
        super.setUp()
        tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try? FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        keychain = DictBasedKeychain()
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: tempDir)
        keychain.removeAllContent()
        super.tearDown()
    }

    // MARK: - Store Type Detection

    func testDetectsPassageStoreWithAgeRecipients() throws {
        // Create .age-recipients file (passage store marker)
        let ageRecipientsFile = tempDir.appendingPathComponent(".age-recipients")
        try "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".write(
            to: ageRecipientsFile,
            atomically: true,
            encoding: .utf8
        )

        let agent = CryptoAgent(storeURL: tempDir, keyStore: keychain)
        XCTAssertEqual(agent.storeType, .passage)
    }

    func testDetectsPassStoreWithGpgId() throws {
        // Create .gpg-id file (pass store marker)
        let gpgIdFile = tempDir.appendingPathComponent(".gpg-id")
        try "ABCD1234".write(to: gpgIdFile, atomically: true, encoding: .utf8)

        let agent = CryptoAgent(storeURL: tempDir, keyStore: keychain)
        XCTAssertEqual(agent.storeType, .pass)
    }

    func testFallsBackToPassForUnknownStore() throws {
        // No marker files - should default to .pass for backwards compatibility
        let agent = CryptoAgent(storeURL: tempDir, keyStore: keychain)
        XCTAssertEqual(agent.storeType, .pass)
    }

    // MARK: - isPrepared Tests

    func testIsPreparedReturnsFalseForPassWithoutKeys() {
        let agent = CryptoAgent(storeURL: tempDir, keyStore: keychain)
        XCTAssertFalse(agent.isPrepared)
    }

    func testIsPreparedReturnsTrueForPassWithKeys() throws {
        // Set up PGP keys in keychain
        keychain.add(string: "PUBLIC_KEY", for: PGPKey.PUBLIC.getKeychainKey())
        keychain.add(string: "PRIVATE_KEY", for: PGPKey.PRIVATE.getKeychainKey())

        let agent = CryptoAgent(storeURL: tempDir, keyStore: keychain)
        XCTAssertTrue(agent.isPrepared)
    }

    func testIsPreparedReturnsFalseForPassageWithoutIdentity() throws {
        // Create passage store marker
        let ageRecipientsFile = tempDir.appendingPathComponent(".age-recipients")
        try "age1test...".write(to: ageRecipientsFile, atomically: true, encoding: .utf8)

        let agent = CryptoAgent(storeURL: tempDir, keyStore: keychain)
        XCTAssertFalse(agent.isPrepared)
    }

    func testIsPreparedReturnsTrueForPassageWithIdentity() throws {
        // Create passage store marker
        let ageRecipientsFile = tempDir.appendingPathComponent(".age-recipients")
        try "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".write(
            to: ageRecipientsFile,
            atomically: true,
            encoding: .utf8
        )

        // Add age identity to keychain
        keychain.add(
            string: "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ",
            for: CryptoAgent.ageIdentityKeychainKey
        )

        let agent = CryptoAgent(storeURL: tempDir, keyStore: keychain)
        XCTAssertTrue(agent.isPrepared)
    }

    // MARK: - Static Shared Instance

    func testSharedInstanceCanBeSet() {
        let agent = CryptoAgent(storeURL: tempDir, keyStore: keychain)
        CryptoAgent.shared = agent

        XCTAssertNotNil(CryptoAgent.shared)
        XCTAssertEqual(CryptoAgent.shared?.storeType, .pass)

        // Clean up
        CryptoAgent.shared = nil
    }

    // MARK: - Error Cases

    func testInitKeysThrowsForPassageWithoutIdentity() throws {
        // Create passage store marker
        let ageRecipientsFile = tempDir.appendingPathComponent(".age-recipients")
        try "age1test...".write(to: ageRecipientsFile, atomically: true, encoding: .utf8)

        let agent = CryptoAgent(storeURL: tempDir, keyStore: keychain)

        XCTAssertThrowsError(try agent.initKeys()) { error in
            XCTAssertEqual(error as? CryptoError, CryptoError.identityNotFound)
        }
    }

    func testDecryptThrowsForUnknownStoreType() throws {
        // This tests that decryption fails gracefully when store type cannot be determined
        // Even though we default to .pass, we should verify error handling works
        let agent = CryptoAgent(storeURL: tempDir, keyStore: keychain)
        let dummyData = Data("encrypted".utf8)

        XCTAssertThrowsError(try agent.decrypt(encryptedData: dummyData) { _ in "" }) { error in
            // Should throw AppError.keyImport since no PGP keys are configured
            XCTAssertEqual(error as? AppError, AppError.keyImport)
        }
    }
}
