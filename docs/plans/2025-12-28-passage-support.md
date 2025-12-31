# Passage Support Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add support for passage (age-encrypted) password stores alongside existing pass (GPG-encrypted) stores, with iOS Secure Enclave key generation for hardware-backed decryption.

**Architecture:** Introduce a `CryptoInterface` protocol abstracting over PGP and age encryption. Create an `AgeInterface` using the Go age library compiled via gomobile. Add `SecureEnclaveIdentity` for hardware-backed P-256 keys exportable as `age1tag1...` recipients. Detect store type by presence of `.gpg-id` vs `.age-recipients` files.

**Tech Stack:**
- Go age library via gomobile → `Age.xcframework`
- CryptoKit `SecureEnclave.P256.KeyAgreement` for Secure Enclave keys
- Bech32 encoding for `age1tag1...` recipient format

---

## Phase 1: Age Crypto Foundation

### Task 1: Build age.xcframework via gomobile

**Files:**
- Create: `scripts/age_build.sh`

**Step 1: Create the age build script**

```bash
#!/bin/bash

set -euox pipefail

AGE_VERSION="v1.2.0"

export GOPATH="$(pwd)/go"
export PATH="$PATH:$GOPATH/bin"

OUTPUT_PATH="go/dist"
CHECKOUT_PATH="go/checkout"
AGE_PATH="$CHECKOUT_PATH/age"

mkdir -p "$OUTPUT_PATH"
mkdir -p "$CHECKOUT_PATH"

git clone --depth 1 --branch "$AGE_VERSION" https://github.com/FiloSottile/age.git "$AGE_PATH"

pushd "$AGE_PATH"
mkdir -p dist

go get golang.org/x/mobile/cmd/gomobile@latest
go get golang.org/x/mobile/cmd/gobind@latest
go build golang.org/x/mobile/cmd/gomobile
go build golang.org/x/mobile/cmd/gobind

./gomobile init
./gomobile bind -tags mobile -target ios -iosversion 13.0 -v -x -ldflags="-s -w" -o dist/Age.xcframework \
  filippo.io/age \
  filippo.io/age/armor
popd

cp -r "$AGE_PATH/dist/Age.xcframework" "$OUTPUT_PATH"
```

**Step 2: Make executable and test build**

Run: `chmod +x scripts/age_build.sh && ./scripts/age_build.sh`
Expected: `go/dist/Age.xcframework` directory created

**Step 3: Add Age.xcframework to Xcode project**

- Open `pass.xcodeproj`
- Drag `go/dist/Age.xcframework` into the project
- Add to passKit target's "Frameworks, Libraries, and Embedded Content"
- Set "Embed & Sign"

**Step 4: Commit**

```bash
git add scripts/age_build.sh
git commit -m "build: add age.xcframework build script

Uses gomobile to compile filippo.io/age for iOS, matching
the existing gopenpgp build approach."
```

---

### Task 2: Create CryptoInterface protocol

**Files:**
- Create: `passKit/Crypto/CryptoInterface.swift`
- Test: `passKitTests/Crypto/CryptoInterfaceTest.swift`

**Step 1: Write the protocol**

```swift
//
//  CryptoInterface.swift
//  passKit
//

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
```

**Step 2: Run build to verify compilation**

Run: `xcodebuild -scheme passKit -destination 'platform=iOS Simulator,name=iPhone 15' build 2>&1 | tail -20`
Expected: BUILD SUCCEEDED

**Step 3: Commit**

```bash
git add passKit/Crypto/CryptoInterface.swift
git commit -m "feat(crypto): add CryptoInterface protocol

Unified abstraction for PGP and age encryption backends."
```

---

### Task 3: Create AgeInterface implementation

**Files:**
- Create: `passKit/Crypto/AgeInterface.swift`
- Create: `passKitTests/Crypto/AgeInterfaceTest.swift`

**Step 1: Write the failing test**

```swift
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
```

**Step 2: Run test to verify it fails**

Run: `xcodebuild test -scheme pass -destination 'platform=iOS Simulator,name=iPhone 15' -only-testing:passKitTests/AgeInterfaceTest 2>&1 | tail -30`
Expected: FAIL - AgeInterface not defined

**Step 3: Write minimal AgeInterface implementation**

```swift
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
```

**Step 4: Run test to verify it passes**

Run: `xcodebuild test -scheme pass -destination 'platform=iOS Simulator,name=iPhone 15' -only-testing:passKitTests/AgeInterfaceTest 2>&1 | tail -30`
Expected: All tests PASSED

**Step 5: Commit**

```bash
git add passKit/Crypto/AgeInterface.swift passKitTests/Crypto/AgeInterfaceTest.swift
git commit -m "feat(crypto): add AgeInterface for age encryption

Wraps Go age library via gomobile for X25519 encrypt/decrypt."
```

---

## Phase 2: Secure Enclave Integration

### Task 4: Implement Bech32 encoding for age1tag format

**Files:**
- Create: `passKit/Crypto/Bech32.swift`
- Create: `passKitTests/Crypto/Bech32Test.swift`

**Step 1: Write the failing test**

```swift
//
//  Bech32Test.swift
//  passKitTests
//

import XCTest
@testable import passKit

final class Bech32Test: XCTestCase {

    func testEncodeDecodeRoundTrip() throws {
        let testData = Data([0x01, 0x02, 0x03, 0x04, 0x05])
        let encoded = try Bech32.encode(hrp: "age1tag", data: testData)

        XCTAssertTrue(encoded.hasPrefix("age1tag1"))

        let (hrp, decoded) = try Bech32.decode(encoded)
        XCTAssertEqual(hrp, "age1tag")
        XCTAssertEqual(decoded, testData)
    }

    func testKnownVector() throws {
        // Test vector from BIP-173
        let data = Data([0x00, 0x14] + Array(repeating: UInt8(0x00), count: 20))
        let encoded = try Bech32.encode(hrp: "bc", data: data)
        XCTAssertEqual(encoded, "bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq9e75rs")
    }

    func testInvalidChecksum() {
        XCTAssertThrowsError(try Bech32.decode("age1tag1qqqqqqqqqqqqqqqinvalid"))
    }
}
```

**Step 2: Run test to verify it fails**

Run: `xcodebuild test -scheme pass -destination 'platform=iOS Simulator,name=iPhone 15' -only-testing:passKitTests/Bech32Test 2>&1 | tail -20`
Expected: FAIL - Bech32 not defined

**Step 3: Implement Bech32**

```swift
//
//  Bech32.swift
//  passKit
//

import Foundation

/// Bech32/Bech32m encoding for age recipient strings
public enum Bech32 {

    public enum Error: Swift.Error {
        case invalidCharacter
        case invalidChecksum
        case invalidLength
        case invalidHRP
    }

    private static let charset = Array("qpzry9x8gf2tvdw0s3jn54khce6mua7l")
    private static let charsetMap: [Character: UInt8] = {
        var map: [Character: UInt8] = [:]
        for (i, c) in charset.enumerated() {
            map[c] = UInt8(i)
        }
        return map
    }()

    public static func encode(hrp: String, data: Data) throws -> String {
        let values = convertTo5Bit(data: data)
        let checksum = createChecksum(hrp: hrp, values: values)
        let combined = values + checksum

        var result = hrp + "1"
        for v in combined {
            result.append(charset[Int(v)])
        }
        return result
    }

    public static func decode(_ string: String) throws -> (hrp: String, data: Data) {
        let lower = string.lowercased()
        guard let separatorIndex = lower.lastIndex(of: "1") else {
            throw Error.invalidHRP
        }

        let hrp = String(lower[..<separatorIndex])
        let dataPartStart = lower.index(after: separatorIndex)
        let dataPart = String(lower[dataPartStart...])

        var values: [UInt8] = []
        for c in dataPart {
            guard let v = charsetMap[c] else {
                throw Error.invalidCharacter
            }
            values.append(v)
        }

        guard verifyChecksum(hrp: hrp, values: values) else {
            throw Error.invalidChecksum
        }

        let dataValues = Array(values.dropLast(6))
        let data = try convertFrom5Bit(values: dataValues)
        return (hrp, data)
    }

    private static func convertTo5Bit(data: Data) -> [UInt8] {
        var result: [UInt8] = []
        var acc: UInt32 = 0
        var bits: UInt32 = 0

        for byte in data {
            acc = (acc << 8) | UInt32(byte)
            bits += 8
            while bits >= 5 {
                bits -= 5
                result.append(UInt8((acc >> bits) & 0x1f))
            }
        }
        if bits > 0 {
            result.append(UInt8((acc << (5 - bits)) & 0x1f))
        }
        return result
    }

    private static func convertFrom5Bit(values: [UInt8]) throws -> Data {
        var result: [UInt8] = []
        var acc: UInt32 = 0
        var bits: UInt32 = 0

        for v in values {
            acc = (acc << 5) | UInt32(v)
            bits += 5
            while bits >= 8 {
                bits -= 8
                result.append(UInt8((acc >> bits) & 0xff))
            }
        }
        return Data(result)
    }

    private static func polymod(_ values: [UInt8]) -> UInt32 {
        let gen: [UInt32] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3]
        var chk: UInt32 = 1
        for v in values {
            let top = chk >> 25
            chk = ((chk & 0x01ff_ffff) << 5) ^ UInt32(v)
            for i in 0..<5 {
                if ((top >> i) & 1) == 1 {
                    chk ^= gen[i]
                }
            }
        }
        return chk
    }

    private static func hrpExpand(_ hrp: String) -> [UInt8] {
        var result: [UInt8] = []
        for c in hrp {
            result.append(UInt8(c.asciiValue! >> 5))
        }
        result.append(0)
        for c in hrp {
            result.append(UInt8(c.asciiValue! & 31))
        }
        return result
    }

    private static func createChecksum(hrp: String, values: [UInt8]) -> [UInt8] {
        let polymodInput = hrpExpand(hrp) + values + [0, 0, 0, 0, 0, 0]
        let polymodResult = polymod(polymodInput) ^ 1
        var result: [UInt8] = []
        for i in 0..<6 {
            result.append(UInt8((polymodResult >> (5 * (5 - i))) & 31))
        }
        return result
    }

    private static func verifyChecksum(hrp: String, values: [UInt8]) -> Bool {
        polymod(hrpExpand(hrp) + values) == 1
    }
}
```

**Step 4: Run test to verify it passes**

Run: `xcodebuild test -scheme pass -destination 'platform=iOS Simulator,name=iPhone 15' -only-testing:passKitTests/Bech32Test 2>&1 | tail -20`
Expected: All tests PASSED

**Step 5: Commit**

```bash
git add passKit/Crypto/Bech32.swift passKitTests/Crypto/Bech32Test.swift
git commit -m "feat(crypto): add Bech32 encoding for age recipient format"
```

---

### Task 5: Create SecureEnclaveIdentity

**Files:**
- Create: `passKit/Crypto/SecureEnclaveIdentity.swift`
- Create: `passKitTests/Crypto/SecureEnclaveIdentityTest.swift`

**Step 1: Write the failing test**

```swift
//
//  SecureEnclaveIdentityTest.swift
//  passKitTests
//

import XCTest
import CryptoKit
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
```

**Step 2: Run test to verify it fails**

Run: `xcodebuild test -scheme pass -destination 'platform=iOS Simulator,name=iPhone 15' -only-testing:passKitTests/SecureEnclaveIdentityTest 2>&1 | tail -20`
Expected: FAIL - SecureEnclaveIdentity not defined

**Step 3: Implement SecureEnclaveIdentity**

```swift
//
//  SecureEnclaveIdentity.swift
//  passKit
//

import CryptoKit
import Foundation
import LocalAuthentication

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
        try? delete(tag: tag)

        var accessFlags: SecAccessControlCreateFlags = [.privateKeyUsage]
        if requireBiometric {
            accessFlags.insert(.biometryCurrentSet)
        }

        let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            accessFlags,
            nil
        )!

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
    public static func delete(tag: String) throws {
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
```

**Step 4: Run test on device (Secure Enclave requires real hardware)**

Note: These tests will skip on simulator. Run on physical device:
Run: `xcodebuild test -scheme pass -destination 'platform=iOS,name=<Your iPhone>' -only-testing:passKitTests/SecureEnclaveIdentityTest`

**Step 5: Commit**

```bash
git add passKit/Crypto/SecureEnclaveIdentity.swift passKitTests/Crypto/SecureEnclaveIdentityTest.swift
git commit -m "feat(crypto): add SecureEnclaveIdentity for hardware-backed keys

Generates P-256 keys in Secure Enclave, exports as age1tag recipients."
```

---

## Phase 3: Store Type Detection

### Task 6: Create PasswordStoreType enum and detection

**Files:**
- Create: `passKit/Models/PasswordStoreType.swift`
- Create: `passKitTests/Models/PasswordStoreTypeTest.swift`

**Step 1: Write the failing test**

```swift
//
//  PasswordStoreTypeTest.swift
//  passKitTests
//

import XCTest
@testable import passKit

final class PasswordStoreTypeTest: XCTestCase {

    var tempDir: URL!

    override func setUp() {
        super.setUp()
        tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try? FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: tempDir)
        super.tearDown()
    }

    func testDetectsPassStore() throws {
        // Create .gpg-id file
        let gpgIdFile = tempDir.appendingPathComponent(".gpg-id")
        try "ABCD1234".write(to: gpgIdFile, atomically: true, encoding: .utf8)

        let storeType = PasswordStoreType.detect(at: tempDir)
        XCTAssertEqual(storeType, .pass)
    }

    func testDetectsPassageStore() throws {
        // Create .age-recipients file
        let ageRecipientsFile = tempDir.appendingPathComponent(".age-recipients")
        try "age1abc123...".write(to: ageRecipientsFile, atomically: true, encoding: .utf8)

        let storeType = PasswordStoreType.detect(at: tempDir)
        XCTAssertEqual(storeType, .passage)
    }

    func testDetectsPassageStoreWithIdentitiesFile() throws {
        // Some passage setups use .age-identities
        let ageIdentitiesFile = tempDir.appendingPathComponent(".age-identities")
        try "AGE-SECRET-KEY-1...".write(to: ageIdentitiesFile, atomically: true, encoding: .utf8)

        let storeType = PasswordStoreType.detect(at: tempDir)
        XCTAssertEqual(storeType, .passage)
    }

    func testUnknownWhenNoMarkerFiles() {
        let storeType = PasswordStoreType.detect(at: tempDir)
        XCTAssertEqual(storeType, .unknown)
    }

    func testFileExtensionForPass() {
        XCTAssertEqual(PasswordStoreType.pass.fileExtension, "gpg")
    }

    func testFileExtensionForPassage() {
        XCTAssertEqual(PasswordStoreType.passage.fileExtension, "age")
    }
}
```

**Step 2: Run test to verify it fails**

Run: `xcodebuild test -scheme pass -destination 'platform=iOS Simulator,name=iPhone 15' -only-testing:passKitTests/PasswordStoreTypeTest 2>&1 | tail -20`
Expected: FAIL - PasswordStoreType not defined

**Step 3: Implement PasswordStoreType**

```swift
//
//  PasswordStoreType.swift
//  passKit
//

import Foundation

/// Type of password store (pass with GPG, or passage with age)
public enum PasswordStoreType: Equatable {
    case pass      // Traditional pass with .gpg files
    case passage   // passage with .age files
    case unknown

    /// File extension for encrypted password files
    public var fileExtension: String {
        switch self {
        case .pass:
            return "gpg"
        case .passage:
            return "age"
        case .unknown:
            return ""
        }
    }

    /// Key/recipient marker filename
    public var recipientFileName: String {
        switch self {
        case .pass:
            return ".gpg-id"
        case .passage:
            return ".age-recipients"
        case .unknown:
            return ""
        }
    }

    /// Detect store type from directory contents
    public static func detect(at url: URL) -> PasswordStoreType {
        let fileManager = FileManager.default

        // Check for .gpg-id (pass)
        let gpgIdPath = url.appendingPathComponent(".gpg-id")
        if fileManager.fileExists(atPath: gpgIdPath.path) {
            return .pass
        }

        // Check for .age-recipients (passage)
        let ageRecipientsPath = url.appendingPathComponent(".age-recipients")
        if fileManager.fileExists(atPath: ageRecipientsPath.path) {
            return .passage
        }

        // Check for .age-identities (alternative passage marker)
        let ageIdentitiesPath = url.appendingPathComponent(".age-identities")
        if fileManager.fileExists(atPath: ageIdentitiesPath.path) {
            return .passage
        }

        return .unknown
    }
}
```

**Step 4: Run test to verify it passes**

Run: `xcodebuild test -scheme pass -destination 'platform=iOS Simulator,name=iPhone 15' -only-testing:passKitTests/PasswordStoreTypeTest 2>&1 | tail -20`
Expected: All tests PASSED

**Step 5: Commit**

```bash
git add passKit/Models/PasswordStoreType.swift passKitTests/Models/PasswordStoreTypeTest.swift
git commit -m "feat(models): add PasswordStoreType for pass/passage detection

Detects store type by presence of .gpg-id vs .age-recipients files."
```

---

### Task 7: Update PasswordEntity to handle .age extension

**Files:**
- Modify: `passKit/Models/PasswordEntity.swift:188`
- Modify: `passKitTests/Models/PasswordEntityTest.swift` (add test)

**Step 1: Write the failing test**

Add to existing `PasswordEntityTest.swift`:

```swift
func testAgeFileExtensionStripped() throws {
    // This tests that .age files are recognized like .gpg files
    let context = CoreDataStack.inMemory.mainContext
    let entity = PasswordEntity(context: context)
    entity.name = "test"
    entity.path = "folder/test.age"
    entity.isDir = false

    // The display name should not include .age
    XCTAssertEqual(entity.name, "test")
}
```

**Step 2: Run test to verify current behavior**

Run: `xcodebuild test -scheme pass -destination 'platform=iOS Simulator,name=iPhone 15' -only-testing:passKitTests/PasswordEntityTest 2>&1 | tail -20`

**Step 3: Update PasswordEntity to handle both extensions**

In `passKit/Models/PasswordEntity.swift`, find line 188 and update:

```swift
// Before:
if (name as NSString).pathExtension == "gpg" {
    passwordEntity.name = (name as NSString).deletingPathExtension
}

// After:
let ext = (name as NSString).pathExtension
if ext == "gpg" || ext == "age" {
    passwordEntity.name = (name as NSString).deletingPathExtension
}
```

**Step 4: Run test to verify it passes**

Run: `xcodebuild test -scheme pass -destination 'platform=iOS Simulator,name=iPhone 15' -only-testing:passKitTests/PasswordEntityTest 2>&1 | tail -20`
Expected: All tests PASSED

**Step 5: Commit**

```bash
git add passKit/Models/PasswordEntity.swift passKitTests/Models/PasswordEntityTest.swift
git commit -m "feat(models): support .age file extension in PasswordEntity

Strips .age extension like .gpg for display names."
```

---

## Phase 4: Integrate with CryptoAgent

### Task 8: Create CryptoAgent to replace/wrap PGPAgent

**Files:**
- Create: `passKit/Crypto/CryptoAgent.swift`
- Create: `passKitTests/Crypto/CryptoAgentTest.swift`

**Step 1: Write the failing test**

```swift
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

    func testDetectsStoreTypeOnInit() throws {
        // Create passage store marker
        let ageRecipientsFile = tempDir.appendingPathComponent(".age-recipients")
        try "age1test...".write(to: ageRecipientsFile, atomically: true, encoding: .utf8)

        let agent = CryptoAgent(storeURL: tempDir, keyStore: keychain)
        XCTAssertEqual(agent.storeType, .passage)
    }

    func testFallsBackToPassForUnknownStore() throws {
        let agent = CryptoAgent(storeURL: tempDir, keyStore: keychain)
        // Default to pass for backwards compatibility
        XCTAssertEqual(agent.storeType, .pass)
    }
}
```

**Step 2: Run test to verify it fails**

Run: `xcodebuild test -scheme pass -destination 'platform=iOS Simulator,name=iPhone 15' -only-testing:passKitTests/CryptoAgentTest 2>&1 | tail -20`
Expected: FAIL - CryptoAgent not defined

**Step 3: Implement CryptoAgent**

```swift
//
//  CryptoAgent.swift
//  passKit
//

import Foundation

/// Unified crypto agent that delegates to PGP or age based on store type
public class CryptoAgent {

    public static var shared: CryptoAgent?

    public let storeType: PasswordStoreType
    private let storeURL: URL
    private let keyStore: KeyStore

    // Lazy-loaded crypto backends
    private var pgpAgent: PGPAgent?
    private var ageInterface: AgeInterface?
    private var secureEnclaveIdentity: SecureEnclaveIdentity?

    public init(storeURL: URL, keyStore: KeyStore = AppKeychain.shared) {
        self.storeURL = storeURL
        self.keyStore = keyStore

        let detected = PasswordStoreType.detect(at: storeURL)
        // Default to pass for backwards compatibility
        self.storeType = detected == .unknown ? .pass : detected
    }

    public var isPrepared: Bool {
        switch storeType {
        case .pass:
            return pgpAgent?.isPrepared ?? PGPAgent(keyStore: keyStore).isPrepared
        case .passage:
            return ageInterface != nil || secureEnclaveIdentity != nil
        case .unknown:
            return false
        }
    }

    public func initKeys() throws {
        switch storeType {
        case .pass:
            if pgpAgent == nil {
                pgpAgent = PGPAgent(keyStore: keyStore)
            }
            try pgpAgent?.initKeys()

        case .passage:
            // Try Secure Enclave first
            if let seIdentity = try? SecureEnclaveIdentity.load(tag: "passforios.age.identity") {
                secureEnclaveIdentity = seIdentity
                return
            }
            // Fall back to software identity from keychain
            if let identityString: String = keyStore.get(for: "age.identity") {
                ageInterface = try AgeInterface(identityString: identityString)
            } else {
                throw CryptoError.identityNotFound
            }

        case .unknown:
            throw CryptoError.invalidIdentity("Unknown store type")
        }
    }

    public func decrypt(
        encryptedData: Data,
        requestPassphrase: @escaping (String) -> String
    ) throws -> Data {
        try initKeys()

        switch storeType {
        case .pass:
            guard let result = try pgpAgent?.decrypt(
                encryptedData: encryptedData,
                requestPGPKeyPassphrase: requestPassphrase
            ) else {
                throw CryptoError.decryptionFailed("PGP decryption returned nil")
            }
            return result

        case .passage:
            // Try Secure Enclave identity first
            if let seIdentity = secureEnclaveIdentity {
                return try decryptWithSecureEnclave(encryptedData: encryptedData, identity: seIdentity)
            }
            // Fall back to software identity
            guard let age = ageInterface else {
                throw CryptoError.identityNotFound
            }
            let passphrase = requestPassphrase("")
            return try age.decrypt(encryptedData: encryptedData, passphrase: passphrase)

        case .unknown:
            throw CryptoError.decryptionFailed("Unknown store type")
        }
    }

    public func encrypt(plainData: Data) throws -> Data {
        try initKeys()

        switch storeType {
        case .pass:
            guard let pgp = pgpAgent else {
                throw CryptoError.encryptionFailed("PGP not initialized")
            }
            return try pgp.encrypt(plainData: plainData)

        case .passage:
            guard let age = ageInterface else {
                throw CryptoError.encryptionFailed("Age not initialized")
            }
            return try age.encrypt(plainData: plainData)

        case .unknown:
            throw CryptoError.encryptionFailed("Unknown store type")
        }
    }

    // MARK: - Secure Enclave decryption

    private func decryptWithSecureEnclave(encryptedData: Data, identity: SecureEnclaveIdentity) throws -> Data {
        // Parse age file header to extract ephemeral key from stanza
        // Perform ECDH, derive file key, decrypt payload
        // This requires parsing the age format - implementation depends on
        // whether we use Go age library or implement in Swift

        // For now, delegate to Go age library with SE callback
        // This is a placeholder - actual implementation needs age format parsing
        throw CryptoError.decryptionFailed("Secure Enclave decryption not yet implemented")
    }
}
```

**Step 4: Run test to verify it passes**

Run: `xcodebuild test -scheme pass -destination 'platform=iOS Simulator,name=iPhone 15' -only-testing:passKitTests/CryptoAgentTest 2>&1 | tail -20`
Expected: All tests PASSED

**Step 5: Commit**

```bash
git add passKit/Crypto/CryptoAgent.swift passKitTests/Crypto/CryptoAgentTest.swift
git commit -m "feat(crypto): add CryptoAgent for unified PGP/age handling

Detects store type and delegates to appropriate crypto backend."
```

---

## Phase 5: UI for Secure Enclave Setup

### Task 9: Add Secure Enclave key generation UI

**Files:**
- Create: `pass/Controllers/SecureEnclaveSetupViewController.swift`
- Modify: `pass/Controllers/SettingsTableViewController.swift` (add entry point)

**Step 1: Create the setup view controller**

```swift
//
//  SecureEnclaveSetupViewController.swift
//  pass
//

import CryptoKit
import passKit
import UIKit

class SecureEnclaveSetupViewController: UITableViewController {

    private var identity: SecureEnclaveIdentity?
    private var recipientString: String = ""

    private enum Section: Int, CaseIterable {
        case status
        case recipient
        case actions
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        title = "Secure Enclave"
        tableView.register(UITableViewCell.self, forCellReuseIdentifier: "cell")
        loadExistingIdentity()
    }

    private func loadExistingIdentity() {
        identity = try? SecureEnclaveIdentity.load(tag: "passforios.age.identity")
        recipientString = identity?.recipient ?? ""
        tableView.reloadData()
    }

    // MARK: - Table View

    override func numberOfSections(in tableView: UITableView) -> Int {
        Section.allCases.count
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        switch Section(rawValue: section)! {
        case .status:
            return 1
        case .recipient:
            return identity != nil ? 1 : 0
        case .actions:
            return identity != nil ? 2 : 1
        }
    }

    override func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        switch Section(rawValue: section)! {
        case .status:
            return "Status"
        case .recipient:
            return identity != nil ? "Your Recipient (for .age-recipients)" : nil
        case .actions:
            return nil
        }
    }

    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "cell", for: indexPath)

        switch Section(rawValue: indexPath.section)! {
        case .status:
            if SecureEnclave.isAvailable {
                cell.textLabel?.text = identity != nil ? "✓ Identity configured" : "No identity"
                cell.textLabel?.textColor = identity != nil ? .systemGreen : .label
            } else {
                cell.textLabel?.text = "Secure Enclave not available"
                cell.textLabel?.textColor = .systemRed
            }
            cell.selectionStyle = .none

        case .recipient:
            cell.textLabel?.text = recipientString
            cell.textLabel?.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
            cell.textLabel?.numberOfLines = 0
            cell.selectionStyle = .default
            cell.accessoryType = .none

        case .actions:
            if indexPath.row == 0 {
                cell.textLabel?.text = identity != nil ? "Regenerate Identity" : "Generate Identity"
                cell.textLabel?.textColor = .systemBlue
            } else {
                cell.textLabel?.text = "Delete Identity"
                cell.textLabel?.textColor = .systemRed
            }
            cell.selectionStyle = .default
        }

        return cell
    }

    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)

        switch Section(rawValue: indexPath.section)! {
        case .recipient:
            copyRecipient()
        case .actions:
            if indexPath.row == 0 {
                generateIdentity()
            } else {
                deleteIdentity()
            }
        default:
            break
        }
    }

    // MARK: - Actions

    private func generateIdentity() {
        let alert = UIAlertController(
            title: "Generate Identity?",
            message: "This will create a new Secure Enclave key. Add the recipient to your .age-recipients file to encrypt passwords to this device.",
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: "Cancel", style: .cancel))
        alert.addAction(UIAlertAction(title: "Generate", style: .default) { [weak self] _ in
            self?.doGenerate()
        })
        present(alert, animated: true)
    }

    private func doGenerate() {
        do {
            identity = try SecureEnclaveIdentity.generate(
                tag: "passforios.age.identity",
                requireBiometric: true
            )
            recipientString = identity?.recipient ?? ""
            tableView.reloadData()

            // Offer to copy
            let alert = UIAlertController(
                title: "Identity Generated",
                message: "Copy the recipient string to add to your .age-recipients file?",
                preferredStyle: .alert
            )
            alert.addAction(UIAlertAction(title: "Copy", style: .default) { [weak self] _ in
                self?.copyRecipient()
            })
            alert.addAction(UIAlertAction(title: "Later", style: .cancel))
            present(alert, animated: true)
        } catch {
            showError(error)
        }
    }

    private func copyRecipient() {
        UIPasteboard.general.string = recipientString
        let alert = UIAlertController(title: "Copied", message: nil, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "OK", style: .default))
        present(alert, animated: true)
    }

    private func deleteIdentity() {
        let alert = UIAlertController(
            title: "Delete Identity?",
            message: "You will no longer be able to decrypt passwords encrypted to this device.",
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: "Cancel", style: .cancel))
        alert.addAction(UIAlertAction(title: "Delete", style: .destructive) { [weak self] _ in
            try? SecureEnclaveIdentity.delete(tag: "passforios.age.identity")
            self?.identity = nil
            self?.recipientString = ""
            self?.tableView.reloadData()
        })
        present(alert, animated: true)
    }

    private func showError(_ error: Error) {
        let alert = UIAlertController(
            title: "Error",
            message: error.localizedDescription,
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: "OK", style: .default))
        present(alert, animated: true)
    }
}
```

**Step 2: Add entry point in Settings**

Add to SettingsTableViewController a new row that pushes SecureEnclaveSetupViewController.

**Step 3: Commit**

```bash
git add pass/Controllers/SecureEnclaveSetupViewController.swift
git commit -m "feat(ui): add Secure Enclave setup screen

Allows generating age identity in Secure Enclave and copying recipient."
```

---

## Future Tasks (Phase 6+)

### Task 10: Implement age file format parser for Secure Enclave decryption

Parse age header to extract `age1tag` stanzas, perform ECDH with Secure Enclave, unwrap file key.

### Task 11: Add YubiKey PIV support

Implement PIV APDU commands, P-256 ECDH on YubiKey, integrate with age decryption.

### Task 12: Update PasswordStore to use CryptoAgent

Replace PGPAgent.shared references with CryptoAgent.shared throughout the codebase.

### Task 13: Add UI for importing age identities

Allow importing `AGE-SECRET-KEY-*` identity strings for software-based decryption.

---

## Testing Checklist

- [ ] Age.xcframework builds successfully
- [ ] AgeInterface encrypt/decrypt works with test keys
- [ ] Bech32 encoding matches age1tag format spec
- [ ] SecureEnclaveIdentity generates valid recipients (on device)
- [ ] PasswordStoreType correctly detects .gpg-id vs .age-recipients
- [ ] CryptoAgent routes to correct backend based on store type
- [ ] UI allows generating and copying Secure Enclave recipient
- [ ] End-to-end: decrypt .age file encrypted on desktop to SE recipient
