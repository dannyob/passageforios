// Package sshage provides high-level verification for .age-recipients changes.
//
// This file provides the main entry points for verifying trust during
// .age-recipients file modifications. The API is designed to be used by:
// - Shell scripts via a CLI tool
// - iOS app via gomobile bindings
//
// Trust Model:
// - Normal commits: the signer must be in the PREVIOUS .age-recipients list
// - Bootstrap commits: the signer must be in THEIR OWN new .age-recipients list
package sshage

import (
	"errors"
	"fmt"
	"strings"
)

// Errors for verification
var (
	// ErrSignatureVerificationFailed is returned when cryptographic verification fails.
	ErrSignatureVerificationFailed = errors.New("signature verification failed")
)

// VerifyRecipientsChange verifies that a commit modifying .age-recipients is authorized.
// It extracts the signer's SSH public key, converts to age format, and checks authorization.
//
// This implements the trust rule for NORMAL commits (not bootstrap):
// The signer must be present in the PREVIOUS .age-recipients file.
//
// Parameters:
//   - signature: armored SSH signature from the git commit
//   - signedData: the commit data that was signed
//   - authorizedRecipients: list of age recipients who are authorized to make changes
//     (typically from the PREVIOUS .age-recipients file)
//   - verifySignature: if true, also verify the cryptographic signature
//
// Returns:
//   - signerAgeKey: the signer's age recipient string
//   - authorized: true if the signer is in the authorized list
//   - error: any error during processing
func VerifyRecipientsChange(signature string, signedData []byte, authorizedRecipients []string, verifySignature bool) (signerAgeKey string, authorized bool, err error) {
	// Step 1: Extract the signer's SSH public key from the signature
	sshPubKey, err := ExtractSignerSSHPublicKey(signature)
	if err != nil {
		return "", false, fmt.Errorf("extracting signer public key: %w", err)
	}

	// Step 2: Convert SSH public key to age recipient format
	signerAgeKey, err = SSHPublicKeyToAgeRecipient(sshPubKey)
	if err != nil {
		return "", false, fmt.Errorf("converting to age recipient: %w", err)
	}

	// Step 3: Optionally verify the cryptographic signature
	if verifySignature {
		valid, verifyErr := VerifySSHSignature(signature, signedData)
		if verifyErr != nil {
			return signerAgeKey, false, fmt.Errorf("%w: %v", ErrSignatureVerificationFailed, verifyErr)
		}
		if !valid {
			return signerAgeKey, false, ErrSignatureVerificationFailed
		}
	}

	// Step 4: Check if the signer is in the authorized list
	authorized = isKeyInRecipientsList(signerAgeKey, authorizedRecipients)

	return signerAgeKey, authorized, nil
}

// IsBootstrapValid checks if a bootstrap commit is self-consistent.
// The signer's age key must be in the new recipients list.
//
// This implements the trust rule for BOOTSTRAP commits:
// Since there's no previous .age-recipients file, we trust the commit if
// the signer includes themselves in the new recipients list. This is
// self-consistent and prevents someone from creating a recipients file
// that excludes themselves (which would be suspicious).
//
// Parameters:
//   - signature: armored SSH signature from the git commit
//   - signedData: the commit data that was signed
//   - newRecipients: list of age recipients in the NEW .age-recipients file
//   - verifySignature: if true, also verify the cryptographic signature
//
// Returns:
//   - signerAgeKey: the signer's age recipient string
//   - valid: true if the signer is in the new recipients list
//   - error: any error during processing
func IsBootstrapValid(signature string, signedData []byte, newRecipients []string, verifySignature bool) (signerAgeKey string, valid bool, err error) {
	// The logic is identical to VerifyRecipientsChange, just with different semantics:
	// - VerifyRecipientsChange checks against the PREVIOUS recipients (who can authorize changes)
	// - IsBootstrapValid checks against the NEW recipients (self-consistency check)
	return VerifyRecipientsChange(signature, signedData, newRecipients, verifySignature)
}

// isKeyInRecipientsList checks if an age key is present in a list of recipients.
// Handles whitespace trimming for robustness.
func isKeyInRecipientsList(key string, recipients []string) bool {
	key = strings.TrimSpace(key)
	for _, recipient := range recipients {
		if strings.TrimSpace(recipient) == key {
			return true
		}
	}
	return false
}
