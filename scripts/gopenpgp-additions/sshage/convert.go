// Package sshage provides conversion between SSH ed25519 public keys and age recipients.
//
// This is used for the trust verification system in Pass for iOS. When we extract
// a signer's SSH public key from a git commit signature, we need to convert it
// to age format to compare against .age-recipients.
//
// The math: Ed25519 uses twisted Edwards curve, age uses X25519 (Montgomery).
// Same underlying group, different representations. The edwards25519.Point.BytesMontgomery()
// method handles this conversion.
package sshage

import (
	"errors"
	"fmt"
	"strings"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/ssh"
)

// ErrNotEd25519 is returned when the SSH key is not an ed25519 key.
var ErrNotEd25519 = errors.New("only ed25519 SSH keys can be converted to age recipients")

// ErrInvalidKey is returned when the SSH key cannot be parsed.
var ErrInvalidKey = errors.New("invalid SSH public key")

// SSHPublicKeyToAgeRecipient converts an SSH ed25519 public key (in authorized_keys format)
// to an age recipient string.
//
// The conversion process:
// 1. Parse SSH authorized_keys format
// 2. Verify key type is ed25519
// 3. Convert Edwards25519 point to Montgomery/X25519 form
// 4. Bech32 encode with "age" HRP
func SSHPublicKeyToAgeRecipient(sshPubkey []byte) (string, error) {
	if len(sshPubkey) == 0 {
		return "", ErrInvalidKey
	}

	// Parse the SSH public key
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(sshPubkey)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}

	// Check if it's an ed25519 key
	if pubKey.Type() != "ssh-ed25519" {
		return "", fmt.Errorf("%w: got %s", ErrNotEd25519, pubKey.Type())
	}

	// Get the raw ed25519 public key bytes
	// The ssh.PublicKey for ed25519 has the format: string type + string key
	// We need to extract just the 32-byte key
	cryptoPubKey, ok := pubKey.(ssh.CryptoPublicKey)
	if !ok {
		return "", fmt.Errorf("%w: cannot extract crypto public key", ErrInvalidKey)
	}

	ed25519PubKey, ok := cryptoPubKey.CryptoPublicKey().(interface{ Bytes() []byte })
	if !ok {
		// Fallback for older Go versions - extract from marshal format
		marshaled := pubKey.Marshal()
		if len(marshaled) < 51 { // 4 bytes length + 11 bytes "ssh-ed25519" + 4 bytes length + 32 bytes key
			return "", fmt.Errorf("%w: invalid ed25519 key length", ErrInvalidKey)
		}
		// The format is: uint32(len("ssh-ed25519")) + "ssh-ed25519" + uint32(32) + key
		// Skip to the key bytes at offset 4 + 11 + 4 = 19
		return convertEd25519ToAge(marshaled[19:51])
	}

	keyBytes := ed25519PubKey.Bytes()
	if len(keyBytes) != 32 {
		return "", fmt.Errorf("%w: ed25519 key must be 32 bytes, got %d", ErrInvalidKey, len(keyBytes))
	}

	return convertEd25519ToAge(keyBytes)
}

// convertEd25519ToAge converts raw ed25519 public key bytes to an age recipient string.
func convertEd25519ToAge(ed25519Bytes []byte) (string, error) {
	if len(ed25519Bytes) != 32 {
		return "", fmt.Errorf("ed25519 key must be 32 bytes, got %d", len(ed25519Bytes))
	}

	// Convert Edwards25519 point to Montgomery/X25519 form
	point, err := new(edwards25519.Point).SetBytes(ed25519Bytes)
	if err != nil {
		return "", fmt.Errorf("invalid ed25519 point: %w", err)
	}

	// Get the X25519 (Montgomery) representation
	x25519Bytes := point.BytesMontgomery()

	// Bech32 encode with "age" HRP
	encoded, err := bech32Encode("age", x25519Bytes)
	if err != nil {
		return "", fmt.Errorf("bech32 encoding failed: %w", err)
	}

	return encoded, nil
}

// bech32Encode encodes data with the given human-readable part using bech32.
func bech32Encode(hrp string, data []byte) (string, error) {
	// Convert 8-bit data to 5-bit groups
	converted := convertBits(data, 8, 5, true)

	// Calculate checksum
	checksum := bech32Checksum(hrp, converted)

	// Combine data and checksum
	combined := append(converted, checksum...)

	// Build the result string
	var result strings.Builder
	result.WriteString(hrp)
	result.WriteByte('1') // separator

	const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	for _, b := range combined {
		result.WriteByte(charset[b])
	}

	return result.String(), nil
}

// convertBits converts a byte slice from one bit grouping to another.
func convertBits(data []byte, fromBits, toBits int, pad bool) []byte {
	var result []byte
	acc := 0
	bits := 0

	maxv := (1 << toBits) - 1

	for _, b := range data {
		acc = (acc << fromBits) | int(b)
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			result = append(result, byte((acc>>bits)&maxv))
		}
	}

	if pad && bits > 0 {
		result = append(result, byte((acc<<(toBits-bits))&maxv))
	}

	return result
}

// bech32Checksum calculates the bech32 checksum for the given HRP and data.
func bech32Checksum(hrp string, data []byte) []byte {
	values := bech32HrpExpand(hrp)
	values = append(values, data...)
	values = append(values, []byte{0, 0, 0, 0, 0, 0}...)

	polymod := bech32Polymod(values) ^ 1

	checksum := make([]byte, 6)
	for i := 0; i < 6; i++ {
		checksum[i] = byte((polymod >> (5 * (5 - i))) & 31)
	}

	return checksum
}

// bech32HrpExpand expands the HRP for checksum calculation.
func bech32HrpExpand(hrp string) []byte {
	result := make([]byte, len(hrp)*2+1)
	for i, c := range hrp {
		result[i] = byte(c >> 5)
		result[i+len(hrp)+1] = byte(c & 31)
	}
	result[len(hrp)] = 0
	return result
}

// bech32Polymod calculates the bech32 polymod checksum.
func bech32Polymod(values []byte) int {
	generator := []int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := 1

	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ int(v)
		for i := 0; i < 5; i++ {
			if (top>>i)&1 == 1 {
				chk ^= generator[i]
			}
		}
	}

	return chk
}
