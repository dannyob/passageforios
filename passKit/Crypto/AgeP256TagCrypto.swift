//
//  AgeP256TagCrypto.swift
//  passKit
//
//  Implements age p256tag (age1tag) encryption/decryption using CryptoKit HPKE.
//  Compatible with C2SP age specification and age-plugin-se.
//

import CryptoKit
import Foundation

/// Represents a parsed age recipient stanza
public struct AgeStanza {
    public let type: String
    public let args: [String]
    public let body: Data
}

/// Parsed age header result
public struct AgeHeader {
    public let stanzas: [AgeStanza]
    public let payload: Data
}

/// Errors that can occur during p256tag operations
public enum AgeP256TagError: LocalizedError {
    case invalidHeader(String)
    case unsupportedVersion(String)
    case noMatchingStanza
    case invalidStanza(String)
    case hpkeError(String)
    case payloadError(String)

    public var errorDescription: String? {
        switch self {
        case let .invalidHeader(msg):
            return "Invalid age header: \(msg)"
        case let .unsupportedVersion(version):
            return "Unsupported age version: \(version)"
        case .noMatchingStanza:
            return "No matching p256tag stanza found"
        case let .invalidStanza(msg):
            return "Invalid stanza: \(msg)"
        case let .hpkeError(msg):
            return "HPKE error: \(msg)"
        case let .payloadError(msg):
            return "Payload error: \(msg)"
        }
    }
}

@available(iOS 14.0, *)
public class AgeP256TagCrypto {
    private static let ageVersion = "age-encryption.org/v1"
    private static let headerEnd = "---"
    private static let tagSalt = Data("age-encryption.org/p256tag".utf8)

    // MARK: - Tag Operations

    /// Compute tag from encapsulated key and recipient
    /// tag = HKDF-Extract(enc || SHA256(recipient)[:4], salt)[:4]
    public static func computeTag(enc: Data, recipient: Data) throws -> Data {
        let recipientHash = SHA256.hash(data: recipient)
        let recipientHashPrefix = Data(recipientHash.prefix(4))

        let ikm = enc + recipientHashPrefix

        // HKDF-Extract with SHA256
        let prk = HKDF<SHA256>.extract(inputKeyMaterial: SymmetricKey(data: ikm), salt: tagSalt)

        // Take first 4 bytes
        return prk.withUnsafeBytes { bytes in
            Data(bytes.prefix(4))
        }
    }

    /// Verify that a tag matches the given enc and recipient
    public static func verifyTag(_ tag: Data, enc: Data, recipient: Data) throws -> Bool {
        let computed = try computeTag(enc: enc, recipient: recipient)
        return tag == computed
    }

    // MARK: - HPKE Operations

    private static let hpkeInfo = Data("age-encryption.org/p256tag".utf8)

    /// The HPKE ciphersuite for p256tag: P256 + HKDF-SHA256 + ChaCha20Poly1305
    @available(iOS 17.0, *) private static var hpkeCiphersuite: HPKE.Ciphersuite {
        HPKE.Ciphersuite(kem: .P256_HKDF_SHA256, kdf: .HKDF_SHA256, aead: .chaChaPoly)
    }

    /// Wrap file key to a P-256 public key using native CryptoKit HPKE
    /// Returns (enc: ephemeral public key, wrapped: encrypted file key)
    @available(iOS 17.0, *)
    public static func wrapFileKey(
        _ fileKey: SymmetricKey,
        to publicKey: P256.KeyAgreement.PublicKey
    ) throws -> (enc: Data, wrapped: Data) {
        do {
            let fileKeyData = fileKey.withUnsafeBytes { Data($0) }

            // Use native HPKE sender
            var sender = try HPKE.Sender(
                recipientKey: publicKey,
                ciphersuite: hpkeCiphersuite,
                info: hpkeInfo
            )

            let wrapped = try sender.seal(fileKeyData)
            let enc = sender.encapsulatedKey

            return (enc, wrapped)
        } catch let error as AgeP256TagError {
            throw error
        } catch {
            throw AgeP256TagError.hpkeError("wrap failed: \(error.localizedDescription)")
        }
    }

    /// Unwrap file key using Secure Enclave identity
    @available(iOS 17.0, *)
    public static func unwrapFileKey(
        enc: Data,
        wrappedKey: Data,
        identity: SecureEnclaveIdentity
    ) throws -> SymmetricKey {
        do {
            // Use native HPKE recipient with SE private key
            var recipient = try HPKE.Recipient(
                privateKey: identity.privateKey,
                ciphersuite: hpkeCiphersuite,
                info: hpkeInfo,
                encapsulatedKey: enc
            )

            let fileKeyData = try recipient.open(wrappedKey)
            return SymmetricKey(data: fileKeyData)
        } catch let error as AgeP256TagError {
            throw error
        } catch {
            throw AgeP256TagError.hpkeError("unwrap failed: \(error.localizedDescription)")
        }
    }

    // MARK: - Payload Encryption (STREAM)

    private static let streamNonceSize = 12
    private static let streamTagSize = 16
    private static let streamChunkSize = 64 * 1024 // 64 KiB
    private static let payloadNonceSize = 16

    /// Derive STREAM key from file key and payload nonce
    private static func deriveStreamKey(_ fileKey: SymmetricKey, payloadNonce: Data) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: fileKey,
            salt: payloadNonce,
            info: Data("payload".utf8),
            outputByteCount: 32
        )
    }

    /// Build STREAM nonce from counter and final flag
    private static func streamNonce(counter: UInt64, isFinal: Bool) -> Data {
        // First 11 bytes: big-endian counter
        var nonce = Data(count: 11)
        var counterValue = counter
        for idx in (0 ..< 11).reversed() {
            nonce[idx] = UInt8(counterValue & 0xFF)
            counterValue >>= 8
        }
        // Last byte: 0x01 for final, 0x00 otherwise
        nonce.append(isFinal ? 0x01 : 0x00)
        return nonce
    }

    /// Encrypt payload using age STREAM
    public static func encryptPayload(_ plaintext: Data, fileKey: SymmetricKey) throws -> Data {
        // Generate random payload nonce
        var payloadNonce = Data(count: payloadNonceSize)
        _ = payloadNonce.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, payloadNonceSize, $0.baseAddress!) }

        let key = deriveStreamKey(fileKey, payloadNonce: payloadNonce)

        var result = payloadNonce
        var offset = 0
        var counter: UInt64 = 0

        while offset < plaintext.count {
            let remaining = plaintext.count - offset
            let chunkSize = min(remaining, streamChunkSize)
            let isFinal = offset + chunkSize >= plaintext.count

            let chunk = plaintext[offset ..< offset + chunkSize]
            let nonce = streamNonce(counter: counter, isFinal: isFinal)

            do {
                let chachaNonce = try ChaChaPoly.Nonce(data: nonce)
                let sealed = try ChaChaPoly.seal(chunk, using: key, nonce: chachaNonce)
                result.append(sealed.ciphertext)
                result.append(sealed.tag)
            } catch {
                throw AgeP256TagError.payloadError("encrypt failed: \(error.localizedDescription)")
            }

            offset += chunkSize
            counter += 1
        }

        // Handle empty payload
        if plaintext.isEmpty {
            let nonce = streamNonce(counter: 0, isFinal: true)
            do {
                let chachaNonce = try ChaChaPoly.Nonce(data: nonce)
                let sealed = try ChaChaPoly.seal(Data(), using: key, nonce: chachaNonce)
                result.append(sealed.ciphertext)
                result.append(sealed.tag)
            } catch {
                throw AgeP256TagError.payloadError("encrypt failed: \(error.localizedDescription)")
            }
        }

        return result
    }

    /// Decrypt payload using age STREAM
    public static func decryptPayload(_ encrypted: Data, fileKey: SymmetricKey) throws -> Data {
        // Normalize to a fresh Data to avoid slice indexing issues
        let payload = Data(encrypted)

        guard payload.count >= payloadNonceSize else {
            throw AgeP256TagError.payloadError("encrypted data too short for nonce")
        }

        // Extract payload nonce (first 16 bytes)
        let payloadNonce = payload.prefix(payloadNonceSize)
        let key = deriveStreamKey(fileKey, payloadNonce: payloadNonce)

        var result = Data()
        var offset = payloadNonceSize
        var counter: UInt64 = 0

        while offset < payload.count {
            let remaining = payload.count - offset
            // Each chunk is ciphertext + 16-byte tag
            // Max chunk = 64KB ciphertext + 16 bytes tag
            let maxChunkWithTag = streamChunkSize + streamTagSize

            // Determine chunk size (last chunk may be smaller)
            let chunkWithTag = min(remaining, maxChunkWithTag)

            guard chunkWithTag >= streamTagSize else {
                throw AgeP256TagError.payloadError("chunk too small for tag")
            }

            let ciphertextSize = chunkWithTag - streamTagSize
            let isFinal = offset + chunkWithTag >= payload.count

            let ciphertext = payload[offset ..< offset + ciphertextSize]
            let tag = payload[offset + ciphertextSize ..< offset + chunkWithTag]

            let nonce = streamNonce(counter: counter, isFinal: isFinal)

            do {
                let chachaNonce = try ChaChaPoly.Nonce(data: nonce)
                let sealedBox = try ChaChaPoly.SealedBox(nonce: chachaNonce, ciphertext: ciphertext, tag: tag)
                let decrypted = try ChaChaPoly.open(sealedBox, using: key)
                result.append(decrypted)
            } catch {
                throw AgeP256TagError.payloadError("decrypt failed: \(error.localizedDescription)")
            }

            offset += chunkWithTag
            counter += 1
        }

        return result
    }

    // MARK: - Header Parsing

    /// Decode base64 with optional padding (age uses unpadded base64)
    private static func decodeBase64(_ string: String) -> Data? {
        var padded = string
        let remainder = padded.count % 4
        if remainder > 0 {
            padded += String(repeating: "=", count: 4 - remainder)
        }
        return Data(base64Encoded: padded)
    }

    /// Parse age file header, returning stanzas and payload
    /// The payload after --- is binary, so we need to find the header end in raw bytes
    /// The header end line is "---" optionally followed by " <MAC>" and then newline
    public static func parseHeader(_ data: Data) throws -> AgeHeader {
        // Find "\n---" which marks the start of the final line
        let headerEndLineStart = Data("\n---".utf8)
        guard let dashesRange = data.range(of: headerEndLineStart) else {
            // Maybe file starts with --- (no stanzas)?
            if data.starts(with: Data("---".utf8)) {
                // Find the newline after ---
                if let newlineIndex = data.firstIndex(of: 0x0A) {
                    let payload = data.suffix(from: data.index(after: newlineIndex))
                    return try parseHeaderOnly(Data(), payload: payload)
                }
            }
            throw AgeP256TagError.invalidHeader("no header end marker found")
        }

        // Header is everything before the \n---
        let headerData = data.prefix(upTo: dashesRange.lowerBound)

        // Find the newline after --- (could be "---\n" or "--- <MAC>\n")
        let afterDashes = data.suffix(from: dashesRange.upperBound)
        guard let newlineIndex = afterDashes.firstIndex(of: 0x0A) else {
            // No newline after ---, treat rest as end of header
            return try parseHeaderOnly(headerData, payload: Data())
        }

        // Payload starts after the newline
        let payload = afterDashes.suffix(from: afterDashes.index(after: newlineIndex))

        return try parseHeaderOnly(headerData, payload: payload)
    }

    /// Parse the text portion of the header
    private static func parseHeaderOnly(_ headerData: Data, payload: Data) throws -> AgeHeader {
        guard let content = String(data: headerData, encoding: .utf8) else {
            throw AgeP256TagError.invalidHeader("header not valid UTF-8")
        }

        var lines = content.components(separatedBy: "\n")
        guard !lines.isEmpty else {
            throw AgeP256TagError.invalidHeader("empty file")
        }

        // Check version
        let version = lines.removeFirst().trimmingCharacters(in: .whitespaces)
        guard version == ageVersion else {
            throw AgeP256TagError.unsupportedVersion(version)
        }

        // Parse stanzas
        var stanzas: [AgeStanza] = []

        var lineIndex = 0
        while lineIndex < lines.count {
            let line = lines[lineIndex].trimmingCharacters(in: .whitespaces)

            // Skip empty lines
            if line.isEmpty {
                lineIndex += 1
                continue
            }

            // Parse stanza header: -> type arg1 arg2 ...
            if line.hasPrefix("-> ") {
                let parts = String(line.dropFirst(3)).components(separatedBy: " ")
                guard !parts.isEmpty else {
                    throw AgeP256TagError.invalidStanza("empty stanza type")
                }

                let type = parts[0]
                let args = Array(parts.dropFirst())

                // Read body lines until next stanza or end
                var bodyLines: [String] = []
                lineIndex += 1
                while lineIndex < lines.count {
                    let bodyLine = lines[lineIndex].trimmingCharacters(in: .whitespaces)
                    if bodyLine.hasPrefix("-> ") || bodyLine.isEmpty {
                        break
                    }
                    bodyLines.append(bodyLine)
                    lineIndex += 1
                }

                let bodyBase64 = bodyLines.joined()
                let body = decodeBase64(bodyBase64) ?? Data()

                stanzas.append(AgeStanza(type: type, args: args, body: body))
                continue
            }

            lineIndex += 1
        }

        return AgeHeader(stanzas: stanzas, payload: payload)
    }

    // MARK: - Public API

    /// Decrypt an age file encrypted to a p256tag recipient
    @available(iOS 17.0, *)
    public static func decrypt(ageData: Data, identity: SecureEnclaveIdentity) throws -> Data {
        // Parse header
        let header = try parseHeader(ageData)

        // Find matching p256tag stanza
        let recipientData = identity.publicKey.compressedRepresentation

        for stanza in header.stanzas where stanza.type == "p256tag" {
            guard stanza.args.count >= 2 else {
                continue
            }

            let tagBase64 = stanza.args[0]
            let encBase64 = stanza.args[1]

            // age uses unpadded base64
            guard let tag = decodeBase64(tagBase64),
                  let enc = decodeBase64(encBase64) else {
                continue
            }

            // Verify tag matches our recipient
            if try verifyTag(tag, enc: enc, recipient: recipientData) {
                // Unwrap file key
                let fileKey = try unwrapFileKey(enc: enc, wrappedKey: stanza.body, identity: identity)

                // Decrypt payload
                return try decryptPayload(header.payload, fileKey: fileKey)
            }
        }

        throw AgeP256TagError.noMatchingStanza
    }

    /// Encrypt data to one or more p256tag recipients
    @available(iOS 17.0, *)
    public static func encrypt(plaintext: Data, recipients: [P256.KeyAgreement.PublicKey]) throws -> Data {
        guard !recipients.isEmpty else {
            throw AgeP256TagError.invalidStanza("no recipients provided")
        }

        // Generate random file key
        let fileKey = SymmetricKey(size: .bits256)

        // Build header
        var header = "\(ageVersion)\n"

        for recipient in recipients {
            let recipientData = recipient.compressedRepresentation
            let (enc, wrapped) = try wrapFileKey(fileKey, to: recipient)
            let tag = try computeTag(enc: enc, recipient: recipientData)

            // Use unpadded base64 for age compatibility
            let tagBase64 = tag.base64EncodedString().trimmingCharacters(in: CharacterSet(charactersIn: "="))
            let encBase64 = enc.base64EncodedString().trimmingCharacters(in: CharacterSet(charactersIn: "="))
            let bodyBase64 = wrapped.base64EncodedString().trimmingCharacters(in: CharacterSet(charactersIn: "="))

            header += "-> p256tag \(tagBase64) \(encBase64)\n"
            header += "\(bodyBase64)\n"
        }

        // Compute header MAC
        // MAC key = HKDF-SHA256(file_key, salt="", info="header")
        let macKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: fileKey,
            salt: Data(),
            info: Data("header".utf8),
            outputByteCount: 32
        )

        // MAC is computed over header up to and including "---"
        let headerWithDashes = header + headerEnd
        guard let headerBytes = headerWithDashes.data(using: .utf8) else {
            throw AgeP256TagError.invalidHeader("failed to encode header for MAC")
        }

        let mac = HMAC<SHA256>.authenticationCode(for: headerBytes, using: macKey)
        let macBase64 = Data(mac).base64EncodedString().trimmingCharacters(in: CharacterSet(charactersIn: "="))

        header += "\(headerEnd) \(macBase64)\n"

        // Encrypt payload
        let encryptedPayload = try encryptPayload(plaintext, fileKey: fileKey)

        // Combine header and payload
        guard var result = header.data(using: .utf8) else {
            throw AgeP256TagError.invalidHeader("failed to encode header")
        }
        result.append(encryptedPayload)

        return result
    }
}
