//
//  CryptoInterface.swift
//  passKit
//

import Foundation

/// Unified interface for encryption backends (PGP, age)
public protocol CryptoInterface {
    /// Decrypt data using the provided identity/passphrase
    func decrypt(encryptedData: Data, passphrase: String) throws -> Data

    /// Encrypt data to configured recipients
    func encrypt(plainData: Data) throws -> Data

    /// Human-readable identifier for the key/identity
    var identityID: String { get }

    /// Whether this interface is ready to encrypt/decrypt
    var isReady: Bool { get }
}

/// Errors from crypto operations
public enum CryptoError: Error, Equatable {
    case decryptionFailed(String)
    case encryptionFailed(String)
    case invalidIdentity(String)
    case identityNotFound
    case wrongPassphrase
}
