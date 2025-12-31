//
//  SecureEnclaveIdentityTest.swift
//  passKitTests
//

import CryptoKit
import XCTest
@testable import passKit

@available(iOS 16.0, *)
final class SecureEnclaveIdentityTest: XCTestCase {
    func testGenerateIdentityProducesAge1TagRecipient() throws {
        // Skip if Secure Enclave not available (simulator)
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("Secure Enclave not available")
        }

        let identity = try SecureEnclaveIdentity.generate(tag: "test.passforios.identity")

        XCTAssertTrue(identity.recipient.hasPrefix("age1tag1"))
        XCTAssertGreaterThan(identity.recipient.count, 50)
    }

    func testRecipientFormatIsConsistent() throws {
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("Secure Enclave not available")
        }

        let identity = try SecureEnclaveIdentity.generate(tag: "test.passforios.identity2")
        let recipient1 = identity.recipient

        // Load same identity
        let loaded = try SecureEnclaveIdentity.load(tag: "test.passforios.identity2")
        let recipient2 = loaded?.recipient

        XCTAssertEqual(recipient1, recipient2)
    }

    func testRecipientUsesCompressedRepresentation() throws {
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("Secure Enclave not available")
        }

        let identity = try SecureEnclaveIdentity.generate(tag: "test.passforios.compressed")
        let recipient = identity.recipient

        // Decode the recipient to check data length
        // age1tag + 33 bytes compressed = specific bech32 length
        // Compressed P-256 is always 33 bytes (02/03 prefix + 32 byte x-coord)
        XCTAssertTrue(recipient.hasPrefix("age1tag1"))

        // Bech32 encoding of 33 bytes with "age1tag" HRP should be ~62 chars
        // (7 char HRP + 1 separator + ~54 data chars)
        XCTAssertEqual(recipient.count, 62, "Recipient should be 62 chars for 33-byte compressed key")
    }

    func testECDHProducesSharedSecret() throws {
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("Secure Enclave not available")
        }

        let identity = try SecureEnclaveIdentity.generate(tag: "test.passforios.ecdh")

        // Simulate encryption side: ephemeral key
        let ephemeralKey = P256.KeyAgreement.PrivateKey()

        // Get shared secret from identity's perspective
        let sharedSecret = try identity.sharedSecret(with: ephemeralKey.publicKey)

        // Verify: ephemeral side should get same secret
        let expectedSecret = try ephemeralKey.sharedSecretFromKeyAgreement(with: identity.publicKey)

        XCTAssertEqual(sharedSecret, expectedSecret)
    }

    override func tearDown() {
        // Clean up test keys
        SecureEnclaveIdentity.delete(tag: "test.passforios.identity")
        SecureEnclaveIdentity.delete(tag: "test.passforios.identity2")
        SecureEnclaveIdentity.delete(tag: "test.passforios.compressed")
        SecureEnclaveIdentity.delete(tag: "test.passforios.ecdh")
        super.tearDown()
    }
}
