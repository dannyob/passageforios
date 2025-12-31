//
//  SecureEnclaveIdentityTest.swift
//  passKitTests
//

import CryptoKit
import XCTest
@testable import passKit

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
        try? SecureEnclaveIdentity.delete(tag: "test.passforios.identity")
        try? SecureEnclaveIdentity.delete(tag: "test.passforios.identity2")
        try? SecureEnclaveIdentity.delete(tag: "test.passforios.ecdh")
        super.tearDown()
    }
}
