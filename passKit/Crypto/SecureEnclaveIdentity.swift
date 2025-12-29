//
//  SecureEnclaveIdentity.swift
//  passKit
//

import CryptoKit
import Foundation

/// P-256 identity stored in the iOS Secure Enclave, exportable as age1tag recipient
public class SecureEnclaveIdentity {

    private let privateKey: SecureEnclave.P256.KeyAgreement.PrivateKey
    private let tag: String

    public var publicKey: P256.KeyAgreement.PublicKey {
        privateKey.publicKey
    }

    /// The age1tag1... recipient string for this identity
    public var recipient: String {
        let pubKeyData = publicKey.rawRepresentation
        // age1tag format: HRP + compressed P-256 point
        return (try? Bech32.encode(hrp: "age1tag", data: pubKeyData)) ?? ""
    }

    private init(privateKey: SecureEnclave.P256.KeyAgreement.PrivateKey, tag: String) {
        self.privateKey = privateKey
        self.tag = tag
    }

    /// Generate a new Secure Enclave identity
    public static func generate(tag: String, requireBiometric: Bool = false) throws -> SecureEnclaveIdentity {
        // Delete existing key with same tag
        delete(tag: tag)

        var accessFlags: SecAccessControlCreateFlags = [.privateKeyUsage]
        if requireBiometric {
            accessFlags.insert(.biometryCurrentSet)
        }

        var cfError: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            accessFlags,
            &cfError
        ) else {
            throw CryptoError.encryptionFailed("Failed to create access control: \(cfError?.takeRetainedValue().localizedDescription ?? "unknown")")
        }

        let privateKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            compactRepresentable: true,
            accessControl: accessControl
        )

        // Store key reference in keychain
        try storeKeyReference(privateKey.dataRepresentation, tag: tag)

        return SecureEnclaveIdentity(privateKey: privateKey, tag: tag)
    }

    /// Load an existing Secure Enclave identity
    public static func load(tag: String) throws -> SecureEnclaveIdentity? {
        guard let keyData = loadKeyReference(tag: tag) else {
            return nil
        }

        let privateKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: keyData
        )

        return SecureEnclaveIdentity(privateKey: privateKey, tag: tag)
    }

    /// Delete a Secure Enclave identity
    public static func delete(tag: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: tag,
            kSecAttrService as String: "passforios.secureenclave",
        ]
        SecItemDelete(query as CFDictionary)
    }

    /// Perform ECDH key agreement with an ephemeral public key
    public func sharedSecret(with ephemeralPublicKey: P256.KeyAgreement.PublicKey) throws -> SharedSecret {
        try privateKey.sharedSecretFromKeyAgreement(with: ephemeralPublicKey)
    }

    // MARK: - Keychain helpers

    private static func storeKeyReference(_ data: Data, tag: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: tag,
            kSecAttrService as String: "passforios.secureenclave",
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw CryptoError.encryptionFailed("Failed to store key reference: \(status)")
        }
    }

    private static func loadKeyReference(tag: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: tag,
            kSecAttrService as String: "passforios.secureenclave",
            kSecReturnData as String: true,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess else {
            return nil
        }
        return result as? Data
    }
}
