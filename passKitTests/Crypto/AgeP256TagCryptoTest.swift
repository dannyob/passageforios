//
//  AgeP256TagCryptoTest.swift
//  passKitTests
//

import CryptoKit
import XCTest
@testable import passKit

@available(iOS 17.0, *)
final class AgeP256TagCryptoTest: XCTestCase {
    func testParseAgeHeaderWithP256TagStanza() throws {
        // Valid age header with p256tag stanza
        let ageHeader = Data("""
        age-encryption.org/v1
        -> p256tag TE5U 6PoqxV8WBf4lHaXqzU6HJLP0UddKoFBb4HXWH3clo/frIbZtUf2HWPEMbM9E6as
        vF/MO9RxTCnjC5SXKNT7SEJPjVWj4vu21CdwfFcY/WgfT69bJzIhv+DknSGLlWd
        ---
        """.utf8)

        let parsed = try AgeP256TagCrypto.parseHeader(ageHeader)

        XCTAssertEqual(parsed.stanzas.count, 1)
        XCTAssertEqual(parsed.stanzas[0].type, "p256tag")
        XCTAssertEqual(parsed.stanzas[0].args.count, 2)
        XCTAssertEqual(parsed.stanzas[0].args[0], "TE5U") // tag
        XCTAssertFalse(parsed.stanzas[0].body.isEmpty)
    }

    func testParseAgeHeaderMultipleStanzas() throws {
        let ageHeader = Data("""
        age-encryption.org/v1
        -> X25519 abc123
        AAAA
        -> p256tag WXYZ efgh5678
        BBBB
        ---
        """.utf8)

        let parsed = try AgeP256TagCrypto.parseHeader(ageHeader)

        XCTAssertEqual(parsed.stanzas.count, 2)
        XCTAssertEqual(parsed.stanzas[0].type, "X25519")
        XCTAssertEqual(parsed.stanzas[1].type, "p256tag")
    }

    func testParseAgeHeaderInvalidVersion() throws {
        let ageHeader = Data("age-encryption.org/v2\n-> p256tag AA BB\nCC\n---\n".utf8)

        XCTAssertThrowsError(try AgeP256TagCrypto.parseHeader(ageHeader)) { error in
            XCTAssertTrue(error.localizedDescription.contains("version"))
        }
    }

    // MARK: - Tag Verification Tests

    func testComputeTagFromEncAndRecipient() throws {
        // Test vector: known enc + recipient should produce known tag
        // enc is 65 bytes (uncompressed P-256 point)
        let enc = Data(repeating: 0x04, count: 1) + Data(repeating: 0xAB, count: 64)
        // recipient is 33 bytes (compressed P-256 point)
        let recipient = Data(repeating: 0x02, count: 1) + Data(repeating: 0xCD, count: 32)

        let tag = try AgeP256TagCrypto.computeTag(enc: enc, recipient: recipient)

        // Tag should be 4 bytes
        XCTAssertEqual(tag.count, 4)
    }

    func testVerifyTagMatchesRecipient() throws {
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("Secure Enclave not available")
        }

        let identity = try SecureEnclaveIdentity.generate(tag: "test.passforios.tagverify")
        let recipientData = identity.publicKey.compressedRepresentation

        // Create a fake enc (would normally come from HPKE sender)
        let enc = Data(repeating: 0x04, count: 1) + Data(repeating: 0x42, count: 64)

        let tag = try AgeP256TagCrypto.computeTag(enc: enc, recipient: recipientData)

        // Verify returns true for matching recipient
        let matches = try AgeP256TagCrypto.verifyTag(tag, enc: enc, recipient: recipientData)
        XCTAssertTrue(matches)

        // Different recipient should not match
        let otherRecipient = Data(repeating: 0x03, count: 1) + Data(repeating: 0xFF, count: 32)
        let otherMatches = try AgeP256TagCrypto.verifyTag(tag, enc: enc, recipient: otherRecipient)
        XCTAssertFalse(otherMatches)
    }

    // MARK: - HPKE Tests

    func testHPKEWrapUnwrapRoundTrip() throws {
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("Secure Enclave not available")
        }

        // Generate SE identity
        let identity = try SecureEnclaveIdentity.generate(tag: "test.passforios.hpke")

        // Create a file key
        let fileKey = SymmetricKey(size: .bits256)

        // Wrap to the identity's public key
        let (enc, wrapped) = try AgeP256TagCrypto.wrapFileKey(fileKey, to: identity.publicKey)

        // Unwrap using SE identity
        let unwrapped = try AgeP256TagCrypto.unwrapFileKey(enc: enc, wrappedKey: wrapped, identity: identity)

        // Verify round-trip
        XCTAssertEqual(
            fileKey.withUnsafeBytes { Data($0) },
            unwrapped.withUnsafeBytes { Data($0) }
        )
    }

    // MARK: - Payload Encryption Tests

    func testPayloadEncryptDecryptRoundTrip() throws {
        let fileKey = SymmetricKey(size: .bits256)
        let plaintext = Data("Hello, Secure Enclave!".utf8)

        let encrypted = try AgeP256TagCrypto.encryptPayload(plaintext, fileKey: fileKey)
        let decrypted = try AgeP256TagCrypto.decryptPayload(encrypted, fileKey: fileKey)

        XCTAssertEqual(plaintext, decrypted)
    }

    func testPayloadEncryptionProducesNonEmptyOutput() throws {
        let fileKey = SymmetricKey(size: .bits256)
        let plaintext = Data("Test".utf8)

        let encrypted = try AgeP256TagCrypto.encryptPayload(plaintext, fileKey: fileKey)

        XCTAssertGreaterThan(encrypted.count, plaintext.count) // Has nonce + tag overhead
        XCTAssertNotEqual(encrypted, plaintext)
    }

    // MARK: - Full Encrypt/Decrypt Tests

    func testFullEncryptDecryptRoundTrip() throws {
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("Secure Enclave not available")
        }

        let identity = try SecureEnclaveIdentity.generate(tag: "test.passforios.fullroundtrip")
        let plaintext = Data("my secret password".utf8)

        // Encrypt to the identity's public key
        let encrypted = try AgeP256TagCrypto.encrypt(plaintext: plaintext, recipients: [identity.publicKey])

        // Verify it looks like an age file
        XCTAssertTrue(encrypted.starts(with: Data("age-encryption.org/v1".utf8)))

        // Decrypt with the identity
        let decrypted = try AgeP256TagCrypto.decrypt(ageData: encrypted, identity: identity)

        XCTAssertEqual(plaintext, decrypted)
    }

    override func tearDown() {
        SecureEnclaveIdentity.delete(tag: "test.passforios.fullroundtrip")
        SecureEnclaveIdentity.delete(tag: "test.passforios.tagverify")
        SecureEnclaveIdentity.delete(tag: "test.passforios.hpke")
        super.tearDown()
    }
}
