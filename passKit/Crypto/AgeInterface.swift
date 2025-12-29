//
//  AgeInterface.swift
//  passKit
//

import Foundation
import Age  // gomobile-generated framework

public class AgeInterface: CryptoInterface {

    private let identity: AgeIdentity
    private let recipientString: String

    public init(identityString: String) throws {
        guard identityString.hasPrefix("AGE-SECRET-KEY-") else {
            throw CryptoError.invalidIdentity("invalid format")
        }

        var error: NSError?
        guard let identity = AgeParseX25519Identity(identityString, &error) else {
            throw CryptoError.invalidIdentity(error?.localizedDescription ?? "parse failed")
        }
        self.identity = identity
        self.recipientString = identity.recipient().string()
    }

    public var identityID: String {
        String(recipientString.prefix(20)) + "..."
    }

    public var isReady: Bool {
        true
    }

    public func decrypt(encryptedData: Data, passphrase: String) throws -> Data {
        var error: NSError?
        guard let decrypted = AgeDecrypt(encryptedData, identity, &error) else {
            let message = error?.localizedDescription ?? "unknown error"
            if message.contains("no matching") {
                throw CryptoError.decryptionFailed("no matching identity")
            }
            throw CryptoError.decryptionFailed(message)
        }
        return decrypted
    }

    public func encrypt(plainData: Data) throws -> Data {
        var error: NSError?
        guard let recipient = AgeParseX25519Recipient(recipientString, &error) else {
            throw CryptoError.encryptionFailed("invalid recipient")
        }

        guard let encrypted = AgeEncrypt(plainData, recipient, &error) else {
            throw CryptoError.encryptionFailed(error?.localizedDescription ?? "unknown error")
        }
        return encrypted
    }
}
