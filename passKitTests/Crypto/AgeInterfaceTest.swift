//
//  AgeInterfaceTest.swift
//  passKitTests
//

import XCTest
@testable import passKit

final class AgeInterfaceTest: XCTestCase {
    private let testPlaintext = Data("Hello, passage!".utf8)

    // Test identity (DO NOT use in production - for testing only)
    // Generated with: age-keygen
    private let testIdentity = "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"
    private let testRecipient = "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"

    func testEncryptDecryptRoundTrip() throws {
        let ageInterface = try AgeInterface(identityString: testIdentity)

        let encrypted = try ageInterface.encrypt(plainData: testPlaintext)
        let decrypted = try ageInterface.decrypt(encryptedData: encrypted, passphrase: "")

        XCTAssertEqual(decrypted, testPlaintext)
    }

    func testDecryptWithWrongIdentity() throws {
        let ageInterface1 = try AgeInterface(identityString: testIdentity)
        let encrypted = try ageInterface1.encrypt(plainData: testPlaintext)

        // Different identity
        let otherIdentity = "AGE-SECRET-KEY-1XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
        let ageInterface2 = try AgeInterface(identityString: otherIdentity)

        XCTAssertThrowsError(try ageInterface2.decrypt(encryptedData: encrypted, passphrase: "")) { error in
            XCTAssertEqual(error as? CryptoError, CryptoError.decryptionFailed("no matching identity"))
        }
    }

    func testInvalidIdentityFormat() {
        XCTAssertThrowsError(try AgeInterface(identityString: "not-a-valid-identity")) { error in
            XCTAssertEqual(error as? CryptoError, CryptoError.invalidIdentity("invalid format"))
        }
    }
}
