# Secure Enclave Age Encryption (p256tag / age1tag)

## Goal

Enable Passage for iOS to encrypt and decrypt age files using a P-256 private key stored in the iOS Secure Enclave, using the C2SP-standardized `p256tag` recipient type (`age1tag1...` Bech32 format).

## Why

- Private key never leaves hardware - cannot be extracted even with device compromise
- `age1tag` is part of the official [C2SP age specification](https://github.com/C2SP/C2SP/blob/main/age.md)
- Compatible with standard `age` CLI (>= 1.3.0) - native `p256tag` support
- Compatible with [`age-plugin-se`](https://github.com/remko/age-plugin-se) - macOS Secure Enclave users
- Biometric protection optional (Touch ID / Face ID)

## Format

- **Recipient**: `age1tag1...` (Bech32-encoded compressed P-256 public key, 33 bytes)
- **Stanza**: `-> p256tag <tag> <enc>` followed by wrapped file key
- **Crypto**: HPKE with DHKEM(P-256, HKDF-SHA256) + ChaCha20Poly1305

## Compatibility Matrix

| Action | Tool | Works? |
|--------|------|--------|
| Encrypt to iOS SE key | age CLI >= 1.3.0 | ✓ native |
| Encrypt to iOS SE key | age-plugin-se | ✓ |
| Encrypt to macOS SE key | iOS app | ✓ |
| Decrypt iOS SE key | iOS app | ✓ |
| Decrypt macOS SE key | age-plugin-se | ✓ |

## Non-goals

- Post-quantum hybrid (`age1tagpq`) - future work
- Building a macOS plugin binary - use existing age-plugin-se

---

## Architecture

### Components

```
┌─────────────────────────────────────────────────────────────┐
│ SecureEnclaveIdentity.swift (existing)                      │
│  - Generate/load P-256 key in Secure Enclave                │
│  - Export age1tag1... recipient string                      │
│  - FIX: use compressedRepresentation (33 bytes)             │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ AgeP256TagCrypto.swift (new, ~200 lines)                    │
│  - Parse age file header, find p256tag stanza               │
│  - HPKE encrypt/decrypt using CryptoKit                     │
│  - Wrap/unwrap file key                                     │
│  - Encrypt/decrypt payload (STREAM)                         │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ CryptoAgent.swift (existing)                                │
│  - Remove stub, wire up real SE decryption                  │
│  - Route p256tag to AgeP256TagCrypto                        │
│  - X25519 age files still use Go AgeInterface               │
└─────────────────────────────────────────────────────────────┘
```

### Key Dependencies

- `CryptoKit.HPKE` (iOS 17+) - P-256 HPKE operations
- `Security.framework` - Secure Enclave access
- Existing `Bech32.swift` - recipient encoding

### Design Decision: Pure Swift

We implement p256tag entirely in Swift rather than extending the Go bindings because:

1. **SE operations must be Swift** - CryptoKit HPKE with Secure Enclave cannot cross to Go
2. **Age format is simple** - ~100 lines to parse header and stanzas
3. **CryptoKit HPKE is purpose-built** - Apple designed it for hardware-backed HPKE
4. **Cleaner architecture** - No complex Go↔Swift handoffs mid-decrypt
5. **Future-proof** - Could eventually replace Go age entirely for passage stores

The Go path (`AgeInterface`) remains for standard X25519 age files.

---

## Data Flow

### Decryption Flow

```
1. User opens encrypted password file (.age)

2. Parse age header
   ├─ Read "age-encryption.org/v1" header
   ├─ Find stanza: -> p256tag <tag> <enc>
   └─ Read wrapped file key (base64 body)

3. Verify tag matches our recipient
   tag = HKDF(enc || SHA256(recipient)[:4])[:4]

4. HPKE Open (in Secure Enclave)
   ├─ enc = ephemeral P-256 public key (65 bytes uncompressed)
   ├─ SE does ECDH: shared_secret = privkey * enc
   └─ CryptoKit HPKE derives key + unwraps

5. Unwrap file key (32 bytes)

6. Decrypt payload with file key
   └─ Standard age STREAM: ChaCha20-Poly1305
```

### Encryption Flow

```
1. User saves password, we have recipient(s)

2. Generate random file key (32 bytes)

3. For each p256tag recipient:
   ├─ Parse age1tag1... → compressed P-256 point
   ├─ HPKE Seal with recipient public key
   ├─ Compute tag from enc + recipient
   └─ Write stanza: -> p256tag <tag> <enc>

4. Encrypt payload with file key
   └─ Standard age STREAM: ChaCha20-Poly1305

5. Write .age file
```

---

## Implementation Details

### Fix: Recipient Encoding

Current code uses wrong representation:

```swift
// Current (wrong - 64 bytes):
publicKey.rawRepresentation

// Correct (33 bytes, compatible with age-plugin-se):
publicKey.compressedRepresentation
```

### Age File Format

```
age-encryption.org/v1
-> p256tag <tag-base64> <enc-base64>
<wrapped-file-key-base64>
---
<encrypted-payload>
```

- Header: ASCII, LF-terminated
- Stanza: `-> ` prefix, space-separated arguments, body is base64 (64-char lines)
- Separator: `---` optionally followed by MAC
- Payload: Binary, ChaCha20-Poly1305 STREAM

### HPKE Parameters (per C2SP spec)

- **KEM**: DHKEM(P-256, HKDF-SHA256)
- **KDF**: HKDF-SHA256
- **AEAD**: ChaCha20Poly1305
- **Info**: `"age-encryption.org/p256tag"`
- **AAD**: empty

### Tag Derivation

```swift
let tagInput = enc + SHA256(compressedRecipient).prefix(4)
let tag = HKDF.extract(inputKeyMaterial: tagInput,
                       salt: "age-encryption.org/p256tag").prefix(4)
```

### CryptoKit HPKE Usage

```swift
// Decryption
let recipient = try HPKE.Recipient(
    privateKey: sePrivateKey,
    ciphersuite: .P256_HKDF_SHA256_ChaCha20Poly1305,
    info: Data("age-encryption.org/p256tag".utf8),
    encapsulatedKey: enc
)
let fileKey = try recipient.open(wrappedKey, authenticating: Data())

// Encryption
var sender = try HPKE.Sender(
    recipientKey: p256PublicKey,
    ciphersuite: .P256_HKDF_SHA256_ChaCha20Poly1305,
    info: Data("age-encryption.org/p256tag".utf8)
)
let wrappedKey = try sender.seal(fileKey, authenticating: Data())
let enc = sender.encapsulatedKey
```

---

## AgeP256TagCrypto.swift Structure

```swift
import CryptoKit
import Foundation

public class AgeP256TagCrypto {

    // MARK: - Public API

    /// Decrypt an age file encrypted to a p256tag recipient
    public static func decrypt(
        ageData: Data,
        identity: SecureEnclaveIdentity
    ) throws -> Data

    /// Encrypt data to one or more p256tag recipients
    public static func encrypt(
        plaintext: Data,
        recipients: [P256.KeyAgreement.PublicKey]
    ) throws -> Data

    // MARK: - Header Parsing

    /// Parse age header, return stanzas and payload
    private static func parseHeader(_ data: Data) throws -> (stanzas: [Stanza], payload: Data)

    /// Find p256tag stanza matching our identity
    private static func findMatchingStanza(
        _ stanzas: [Stanza],
        identity: SecureEnclaveIdentity
    ) throws -> (tag: Data, enc: Data, body: Data)

    // MARK: - HPKE Operations

    /// Unwrap file key using SE identity
    private static func unwrapFileKey(
        enc: Data,
        wrappedKey: Data,
        identity: SecureEnclaveIdentity
    ) throws -> SymmetricKey

    /// Wrap file key to recipient
    private static func wrapFileKey(
        _ fileKey: SymmetricKey,
        to recipient: P256.KeyAgreement.PublicKey
    ) throws -> (enc: Data, wrapped: Data)

    // MARK: - Payload Encryption (STREAM)

    /// Decrypt payload using file key
    private static func decryptPayload(_ payload: Data, fileKey: SymmetricKey) throws -> Data

    /// Encrypt payload using file key
    private static func encryptPayload(_ plaintext: Data, fileKey: SymmetricKey) throws -> Data
}
```

---

## Testing Strategy

1. **Unit tests for parsing**
   - Valid age headers with p256tag stanza
   - Multiple stanzas (p256tag + X25519)
   - Malformed headers

2. **HPKE round-trip**
   - Encrypt with ephemeral key, decrypt with SE
   - Verify against known test vectors

3. **Compatibility tests**
   - Encrypt with `age` CLI, decrypt with app
   - Encrypt with app, decrypt with `age-plugin-se`

4. **Integration tests**
   - Full encrypt/decrypt cycle through CryptoAgent
   - Password store operations with SE identity

---

## Migration Path

1. **Phase 1**: Fix recipient encoding (one-line change)
2. **Phase 2**: Implement `AgeP256TagCrypto` with decrypt support
3. **Phase 3**: Add encrypt support
4. **Phase 4**: Wire into CryptoAgent, remove stub
5. **Phase 5**: UI for enabling SE identity on existing stores

---

## References

- [C2SP age specification](https://github.com/C2SP/C2SP/blob/main/age.md)
- [age-plugin-se](https://github.com/remko/age-plugin-se)
- [RFC 9180 - HPKE](https://www.rfc-editor.org/rfc/rfc9180.html)
- [CryptoKit HPKE documentation](https://developer.apple.com/documentation/cryptokit/hpke)
