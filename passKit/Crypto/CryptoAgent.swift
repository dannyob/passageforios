//
//  CryptoAgent.swift
//  passKit
//
//  Copyright © 2024 Bob Sun. All rights reserved.
//

import Foundation

/// Unified crypto agent that delegates to PGP or age based on store type.
/// Maintains backwards compatibility by defaulting to PGP for unknown stores.
public class CryptoAgent {

    /// Shared instance for app-wide use
    public static var shared: CryptoAgent?

    /// Keychain key for storing age identity
    public static let ageIdentityKeychainKey = "age.identity"

    /// Keychain key for storing Secure Enclave identity tag
    public static let secureEnclaveIdentityTag = "passforios.age.identity"

    /// The detected store type (passage or pass)
    public let storeType: PasswordStoreType

    /// URL of the password store
    private let storeURL: URL

    /// Keychain for storing keys and identities
    private let keyStore: KeyStore

    // Lazy-loaded crypto backends
    private var pgpAgent: PGPAgent?
    private var ageInterface: AgeInterface?
    private var secureEnclaveIdentity: SecureEnclaveIdentity?

    // Track decryption status for passphrase caching
    private var latestDecryptStatus = true

    /// Initialize CryptoAgent for a password store
    /// - Parameters:
    ///   - storeURL: URL of the password store directory
    ///   - keyStore: KeyStore for credential storage (defaults to AppKeychain)
    public init(storeURL: URL, keyStore: KeyStore = AppKeychain.shared) {
        self.storeURL = storeURL
        self.keyStore = keyStore

        let detected = PasswordStoreType.detect(at: storeURL)
        // Default to .pass for backwards compatibility when store type is unknown
        self.storeType = detected == .unknown ? .pass : detected
    }

    /// Whether the agent is ready to perform crypto operations
    public var isPrepared: Bool {
        switch storeType {
        case .pass:
            return keyStore.contains(key: PGPKey.PUBLIC.getKeychainKey())
                && keyStore.contains(key: PGPKey.PRIVATE.getKeychainKey())

        case .passage:
            // Check for Secure Enclave identity first
            if (try? SecureEnclaveIdentity.load(tag: Self.secureEnclaveIdentityTag)) != nil {
                return true
            }
            // Check for software identity in keychain
            return keyStore.contains(key: Self.ageIdentityKeychainKey)

        case .unknown:
            return false
        }
    }

    /// Initialize crypto keys/identities
    public func initKeys() throws {
        switch storeType {
        case .pass:
            if pgpAgent == nil {
                pgpAgent = PGPAgent(keyStore: keyStore)
            }
            try pgpAgent?.initKeys()

        case .passage:
            // Try Secure Enclave first
            if let seIdentity = try? SecureEnclaveIdentity.load(tag: Self.secureEnclaveIdentityTag) {
                secureEnclaveIdentity = seIdentity
                return
            }
            // Fall back to software identity from keychain
            guard let identityString: String = keyStore.get(for: Self.ageIdentityKeychainKey) else {
                throw CryptoError.identityNotFound
            }
            ageInterface = try AgeInterface(identityString: identityString)

        case .unknown:
            throw CryptoError.invalidIdentity("Unknown store type")
        }
    }

    /// Uninitialize crypto keys/identities
    public func uninitKeys() {
        pgpAgent?.uninitKeys()
        pgpAgent = nil
        ageInterface = nil
        secureEnclaveIdentity = nil
    }

    // MARK: - Decryption

    /// Decrypt data using the appropriate crypto backend
    /// - Parameters:
    ///   - encryptedData: The encrypted data to decrypt
    ///   - keyID: Optional key ID for PGP multi-key support
    ///   - requestPassphrase: Callback to request passphrase if needed
    /// - Returns: Decrypted data
    public func decrypt(
        encryptedData: Data,
        keyID: String? = nil,
        requestPassphrase: @escaping (String) -> String
    ) throws -> Data {
        switch storeType {
        case .pass:
            return try decryptWithPGP(encryptedData: encryptedData, keyID: keyID, requestPassphrase: requestPassphrase)

        case .passage:
            return try decryptWithAge(encryptedData: encryptedData, requestPassphrase: requestPassphrase)

        case .unknown:
            throw CryptoError.decryptionFailed("Unknown store type")
        }
    }

    /// Decrypt with PGP (delegates to PGPAgent)
    private func decryptWithPGP(
        encryptedData: Data,
        keyID: String? = nil,
        requestPassphrase: @escaping (String) -> String
    ) throws -> Data {
        if pgpAgent == nil {
            pgpAgent = PGPAgent(keyStore: keyStore)
        }
        guard let result = try pgpAgent?.decrypt(
            encryptedData: encryptedData,
            keyID: keyID,
            requestPGPKeyPassphrase: requestPassphrase
        ) else {
            throw CryptoError.decryptionFailed("PGP decryption returned nil")
        }
        return result
    }

    /// Decrypt with age (uses AgeInterface or SecureEnclaveIdentity)
    private func decryptWithAge(
        encryptedData: Data,
        requestPassphrase: @escaping (String) -> String
    ) throws -> Data {
        // Try to initialize if not already done
        if ageInterface == nil && secureEnclaveIdentity == nil {
            try initKeys()
        }

        // Try Secure Enclave identity first
        if let seIdentity = secureEnclaveIdentity {
            return try decryptWithSecureEnclave(encryptedData: encryptedData, identity: seIdentity)
        }

        // Fall back to software identity
        guard let age = ageInterface else {
            throw CryptoError.identityNotFound
        }

        // Remember the previous status and set the current status
        let previousDecryptStatus = latestDecryptStatus
        latestDecryptStatus = false

        // Get passphrase (age identities may be passphrase-protected in the future)
        var passphrase = ""
        if !previousDecryptStatus {
            passphrase = requestPassphrase("")
        } else {
            passphrase = keyStore.get(for: Globals.pgpKeyPassphrase) ?? requestPassphrase("")
        }

        let result = try age.decrypt(encryptedData: encryptedData, passphrase: passphrase)
        latestDecryptStatus = true
        return result
    }

    /// Decrypt using Secure Enclave identity
    private func decryptWithSecureEnclave(
        encryptedData: Data,
        identity _: SecureEnclaveIdentity
    ) throws -> Data {
        // Parse age file header to extract ephemeral key from stanza
        // Perform ECDH with Secure Enclave, derive file key, decrypt payload
        // This requires parsing the age format - full implementation depends on
        // whether we use Go age library or implement in Swift

        // For now, this is a placeholder - actual implementation needs age format parsing
        // The age plugin protocol would handle this via age-plugin-se
        throw CryptoError.decryptionFailed("Secure Enclave decryption not yet implemented")
    }

    // MARK: - Encryption

    /// Encrypt data using the appropriate crypto backend
    /// - Parameters:
    ///   - plainData: Data to encrypt
    ///   - keyID: Optional key ID for PGP multi-key support
    /// - Returns: Encrypted data
    public func encrypt(plainData: Data, keyID: String? = nil) throws -> Data {
        switch storeType {
        case .pass:
            return try encryptWithPGP(plainData: plainData, keyID: keyID)

        case .passage:
            return try encryptWithAge(plainData: plainData)

        case .unknown:
            throw CryptoError.encryptionFailed("Unknown store type")
        }
    }

    /// Encrypt with PGP (delegates to PGPAgent)
    private func encryptWithPGP(plainData: Data, keyID: String? = nil) throws -> Data {
        if pgpAgent == nil {
            pgpAgent = PGPAgent(keyStore: keyStore)
        }
        guard let pgp = pgpAgent else {
            throw CryptoError.encryptionFailed("PGP not initialized")
        }
        if let keyID {
            return try pgp.encrypt(plainData: plainData, keyID: keyID)
        }
        return try pgp.encrypt(plainData: plainData)
    }

    /// Encrypt with age (uses AgeInterface)
    private func encryptWithAge(plainData: Data) throws -> Data {
        // Try to initialize if not already done
        if ageInterface == nil {
            try initKeys()
        }

        guard let age = ageInterface else {
            throw CryptoError.encryptionFailed("Age not initialized")
        }
        return try age.encrypt(plainData: plainData)
    }

    // MARK: - Key Management Helpers

    /// Get key IDs for the current crypto backend
    public func getKeyID() throws -> [String] {
        switch storeType {
        case .pass:
            if pgpAgent == nil {
                pgpAgent = PGPAgent(keyStore: keyStore)
            }
            return try pgpAgent?.getKeyID() ?? []

        case .passage:
            if ageInterface == nil && secureEnclaveIdentity == nil {
                try initKeys()
            }
            if let se = secureEnclaveIdentity {
                return [se.recipient]
            }
            if let age = ageInterface {
                return [age.identityID]
            }
            return []

        case .unknown:
            return []
        }
    }

    /// Get short key IDs for display
    public func getShortKeyID() throws -> [String] {
        switch storeType {
        case .pass:
            if pgpAgent == nil {
                pgpAgent = PGPAgent(keyStore: keyStore)
            }
            return try pgpAgent?.getShortKeyID() ?? []

        case .passage:
            // For age, return truncated recipient string
            let keyIDs = try getKeyID()
            return keyIDs.map { id in
                if id.count > 20 {
                    return String(id.prefix(20)) + "..."
                }
                return id
            }

        case .unknown:
            return []
        }
    }
}
