// Package sshage provides SSH signature parsing for git commit verification.
//
// This file handles parsing SSHSIG format signatures to extract the signer's
// public key, which is needed to verify who signed a git commit.
package sshage

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// SSHSIG format magic bytes
var sshsigMagic = []byte("SSHSIG")

// Errors for signature parsing
var (
	ErrInvalidSignature      = errors.New("invalid SSH signature")
	ErrUnsupportedVersion    = errors.New("unsupported SSHSIG version")
	ErrInvalidMagic          = errors.New("invalid SSHSIG magic bytes")
	ErrSignatureTruncated    = errors.New("signature data truncated")
	ErrUnsupportedKeyType    = errors.New("unsupported key type for verification")
	ErrUnsupportedHashAlgo   = errors.New("unsupported hash algorithm")
	ErrWrongNamespace        = errors.New("wrong signature namespace")
)

// SSHSignature represents a parsed SSH signature in SSHSIG format.
// See: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig
type SSHSignature struct {
	// PublicKey is the raw SSH public key blob from the signature
	PublicKey []byte

	// KeyType is the SSH key type (e.g., "ssh-ed25519", "ssh-rsa")
	KeyType string

	// Namespace identifies what was signed (e.g., "git" for git commits)
	Namespace string

	// HashAlgorithm is the hash algorithm used (e.g., "sha256", "sha512")
	HashAlgorithm string

	// Signature is the raw signature blob
	Signature []byte
}

// ParseSSHSignature parses an armored SSH signature in SSHSIG format.
//
// SSHSIG format (from PROTOCOL.sshsig):
//  1. Magic bytes: "SSHSIG" (6 bytes)
//  2. Version: uint32 (must be 1)
//  3. Public key blob: string (length-prefixed)
//  4. Namespace: string (e.g., "git")
//  5. Reserved: string (empty)
//  6. Hash algorithm: string (e.g., "sha512")
//  7. Signature blob: string
func ParseSSHSignature(armored string) (*SSHSignature, error) {
	// Remove armor and decode base64
	data, err := unarmor(armored)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}

	return parseSignatureBytes(data)
}

// unarmor removes the PEM-like armor from an SSH signature and decodes the base64 content.
func unarmor(armored string) ([]byte, error) {
	lines := strings.Split(strings.TrimSpace(armored), "\n")
	if len(lines) < 3 {
		return nil, errors.New("signature too short")
	}

	// Check header and footer
	if !strings.HasPrefix(lines[0], "-----BEGIN SSH SIGNATURE-----") {
		return nil, errors.New("missing BEGIN marker")
	}
	if !strings.HasPrefix(lines[len(lines)-1], "-----END SSH SIGNATURE-----") {
		return nil, errors.New("missing END marker")
	}

	// Join the base64 content (everything between header and footer)
	var b64Content strings.Builder
	for i := 1; i < len(lines)-1; i++ {
		b64Content.WriteString(strings.TrimSpace(lines[i]))
	}

	// Decode base64
	decoded, err := base64.StdEncoding.DecodeString(b64Content.String())
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %w", err)
	}

	return decoded, nil
}

// parseSignatureBytes parses the raw SSHSIG binary format.
func parseSignatureBytes(data []byte) (*SSHSignature, error) {
	if len(data) < 6 {
		return nil, ErrSignatureTruncated
	}

	// Check magic bytes
	if !bytes.Equal(data[:6], sshsigMagic) {
		return nil, ErrInvalidMagic
	}

	offset := 6

	// Read version (uint32, must be 1)
	if len(data) < offset+4 {
		return nil, ErrSignatureTruncated
	}
	version := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	if version != 1 {
		return nil, fmt.Errorf("%w: got version %d", ErrUnsupportedVersion, version)
	}

	// Read public key blob (string)
	pubkeyBlob, newOffset, err := readString(data, offset)
	if err != nil {
		return nil, fmt.Errorf("reading public key: %w", err)
	}
	offset = newOffset

	// Parse the public key to get the key type
	pubKey, err := ssh.ParsePublicKey(pubkeyBlob)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}

	// Read namespace (string)
	namespace, newOffset, err := readString(data, offset)
	if err != nil {
		return nil, fmt.Errorf("reading namespace: %w", err)
	}
	offset = newOffset

	// Read reserved (string, should be empty)
	_, newOffset, err = readString(data, offset)
	if err != nil {
		return nil, fmt.Errorf("reading reserved: %w", err)
	}
	offset = newOffset

	// Read hash algorithm (string)
	hashAlgo, newOffset, err := readString(data, offset)
	if err != nil {
		return nil, fmt.Errorf("reading hash algorithm: %w", err)
	}
	offset = newOffset

	// Read signature blob (string)
	sigBlob, _, err := readString(data, offset)
	if err != nil {
		return nil, fmt.Errorf("reading signature: %w", err)
	}

	return &SSHSignature{
		PublicKey:     pubkeyBlob,
		KeyType:       pubKey.Type(),
		Namespace:     string(namespace),
		HashAlgorithm: string(hashAlgo),
		Signature:     sigBlob,
	}, nil
}

// readString reads a length-prefixed string from the data at the given offset.
// Returns the string bytes, the new offset after reading, and any error.
func readString(data []byte, offset int) ([]byte, int, error) {
	if len(data) < offset+4 {
		return nil, 0, ErrSignatureTruncated
	}

	length := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	if len(data) < offset+int(length) {
		return nil, 0, ErrSignatureTruncated
	}

	value := data[offset : offset+int(length)]
	offset += int(length)

	return value, offset, nil
}

// ExtractSignerSSHPublicKey extracts the signer's public key from an armored
// SSH signature and returns it in authorized_keys format.
//
// This is useful for comparing against known public keys or converting to
// age recipients for trust verification.
func ExtractSignerSSHPublicKey(armored string) ([]byte, error) {
	sig, err := ParseSSHSignature(armored)
	if err != nil {
		return nil, err
	}

	// Parse the public key blob to get an ssh.PublicKey
	pubKey, err := ssh.ParsePublicKey(sig.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parsing extracted public key: %w", err)
	}

	// Format as authorized_keys line (type + base64-encoded key)
	// ssh.MarshalAuthorizedKey adds a newline, so we trim it
	authorizedKey := ssh.MarshalAuthorizedKey(pubKey)
	return bytes.TrimSpace(authorizedKey), nil
}

// VerifySSHSignature verifies an SSH signature against signed data.
//
// The verification process follows PROTOCOL.sshsig:
// 1. Parse the signature to get the public key and signature blob
// 2. Build the "signed data" structure that was actually signed
// 3. Extract the raw ed25519 signature from the signature blob
// 4. Verify using ed25519.Verify()
//
// Returns true if the signature is valid, false if invalid but parseable.
// Returns an error if the signature cannot be parsed or uses unsupported algorithms.
func VerifySSHSignature(armored string, signedData []byte) (bool, error) {
	sig, err := ParseSSHSignature(armored)
	if err != nil {
		return false, err
	}

	// Validate namespace to prevent signature confusion attacks.
	// A signature created for namespace "file" should not verify as a "git" commit signature.
	if sig.Namespace != "git" {
		return false, fmt.Errorf("%w: got %q, expected \"git\"", ErrWrongNamespace, sig.Namespace)
	}

	// Currently only support ed25519
	if sig.KeyType != "ssh-ed25519" {
		return false, fmt.Errorf("%w: %s", ErrUnsupportedKeyType, sig.KeyType)
	}

	// Hash the message according to the hash algorithm
	var messageHash []byte
	switch sig.HashAlgorithm {
	case "sha256":
		h := sha256.Sum256(signedData)
		messageHash = h[:]
	case "sha512":
		h := sha512.Sum512(signedData)
		messageHash = h[:]
	default:
		return false, fmt.Errorf("%w: %s", ErrUnsupportedHashAlgo, sig.HashAlgorithm)
	}

	// Build the signed data structure per PROTOCOL.sshsig
	// This is what the signer actually signed:
	//   Magic: "SSHSIG" (6 bytes, NOT length-prefixed)
	//   Namespace: string (length-prefixed)
	//   Reserved: string (length-prefixed, empty)
	//   Hash algorithm: string (length-prefixed)
	//   Hash: string (length-prefixed)
	var toVerify bytes.Buffer
	toVerify.Write(sshsigMagic)
	writeString(&toVerify, []byte(sig.Namespace))
	writeString(&toVerify, []byte{}) // reserved, empty
	writeString(&toVerify, []byte(sig.HashAlgorithm))
	writeString(&toVerify, messageHash)

	// Extract the raw ed25519 public key (32 bytes) from the SSH public key blob
	// SSH public key format for ed25519: string "ssh-ed25519" + string <32-byte key>
	pubKey, err := extractEd25519PublicKey(sig.PublicKey)
	if err != nil {
		return false, fmt.Errorf("extracting ed25519 public key: %w", err)
	}

	// Extract the raw ed25519 signature (64 bytes) from the signature blob
	// SSH signature format: string "ssh-ed25519" + string <64-byte signature>
	rawSig, err := extractEd25519Signature(sig.Signature)
	if err != nil {
		return false, fmt.Errorf("extracting ed25519 signature: %w", err)
	}

	// Verify the signature
	return ed25519.Verify(pubKey, toVerify.Bytes(), rawSig), nil
}

// writeString writes a length-prefixed string to the buffer.
func writeString(buf *bytes.Buffer, data []byte) {
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(data)))
	buf.Write(length)
	buf.Write(data)
}

// extractEd25519PublicKey extracts the raw 32-byte ed25519 public key from an SSH public key blob.
func extractEd25519PublicKey(blob []byte) (ed25519.PublicKey, error) {
	// Format: string "ssh-ed25519" + string <32-byte key>
	keyType, offset, err := readString(blob, 0)
	if err != nil {
		return nil, err
	}

	if string(keyType) != "ssh-ed25519" {
		return nil, fmt.Errorf("expected ssh-ed25519, got %s", string(keyType))
	}

	keyData, _, err := readString(blob, offset)
	if err != nil {
		return nil, err
	}

	if len(keyData) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid ed25519 public key size: %d", len(keyData))
	}

	return ed25519.PublicKey(keyData), nil
}

// extractEd25519Signature extracts the raw 64-byte ed25519 signature from an SSH signature blob.
func extractEd25519Signature(blob []byte) ([]byte, error) {
	// Format: string "ssh-ed25519" + string <64-byte signature>
	sigType, offset, err := readString(blob, 0)
	if err != nil {
		return nil, err
	}

	if string(sigType) != "ssh-ed25519" {
		return nil, fmt.Errorf("expected ssh-ed25519, got %s", string(sigType))
	}

	sigData, _, err := readString(blob, offset)
	if err != nil {
		return nil, err
	}

	if len(sigData) != ed25519.SignatureSize {
		return nil, fmt.Errorf("invalid ed25519 signature size: %d", len(sigData))
	}

	return sigData, nil
}
