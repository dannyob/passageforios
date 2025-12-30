// Package mobile provides gomobile-compatible bindings for the sshage package.
//
// Gomobile has restrictions on what types can be exported:
// - Basic types (int, string, bool, float, byte slice) are supported
// - Structs with exported fields of supported types work
// - Error as return type works, but not alongside other return values
// - No Go slices except []byte - we use newline-separated strings instead
//
// This package wraps the sshage verification functions with gomobile-friendly types.
package mobile

import (
	"strings"

	"github.com/mssun/passforios/sshage/sshage"
)

// VerificationResult holds the result of a recipient change verification.
// This struct is gomobile-compatible (only basic types).
type VerificationResult struct {
	SignerAgeKey string
	Authorized   bool
	ErrorMessage string // Empty if no error
}

// VerifyRecipientsChange verifies that a commit modifying .age-recipients is authorized.
//
// This implements the trust rule for NORMAL commits (not bootstrap):
// The signer must be present in the PREVIOUS .age-recipients file.
//
// Parameters:
//   - signature: armored SSH signature from the git commit
//   - signedData: the commit data that was signed
//   - authorizedRecipients: newline-separated list of age recipients who are authorized
//     to make changes (typically from the PREVIOUS .age-recipients file)
//   - verifySignature: if true, also verify the cryptographic signature
//
// Returns a VerificationResult with:
//   - SignerAgeKey: the signer's age recipient string
//   - Authorized: true if the signer is in the authorized list
//   - ErrorMessage: any error message (empty if no error)
func VerifyRecipientsChange(signature string, signedData []byte, authorizedRecipients string, verifySignature bool) *VerificationResult {
	recipients := splitRecipients(authorizedRecipients)

	signerKey, authorized, err := sshage.VerifyRecipientsChange(signature, signedData, recipients, verifySignature)

	result := &VerificationResult{
		SignerAgeKey: signerKey,
		Authorized:   authorized,
	}
	if err != nil {
		result.ErrorMessage = err.Error()
	}
	return result
}

// IsBootstrapValid checks if a bootstrap commit is self-consistent.
//
// This implements the trust rule for BOOTSTRAP commits:
// Since there's no previous .age-recipients file, we trust the commit if
// the signer includes themselves in the new recipients list.
//
// Parameters:
//   - signature: armored SSH signature from the git commit
//   - signedData: the commit data that was signed
//   - newRecipients: newline-separated list of age recipients in the NEW .age-recipients file
//   - verifySignature: if true, also verify the cryptographic signature
//
// Returns a VerificationResult with:
//   - SignerAgeKey: the signer's age recipient string
//   - Authorized: true if the signer is in the new recipients list
//   - ErrorMessage: any error message (empty if no error)
func IsBootstrapValid(signature string, signedData []byte, newRecipients string, verifySignature bool) *VerificationResult {
	recipients := splitRecipients(newRecipients)

	signerKey, valid, err := sshage.IsBootstrapValid(signature, signedData, recipients, verifySignature)

	result := &VerificationResult{
		SignerAgeKey: signerKey,
		Authorized:   valid,
	}
	if err != nil {
		result.ErrorMessage = err.Error()
	}
	return result
}

// SSHPublicKeyToAgeRecipient converts an SSH ed25519 public key to an age recipient.
//
// The input should be in authorized_keys format (e.g., "ssh-ed25519 AAAA... comment").
// Returns the age recipient string (e.g., "age1...") or an error.
func SSHPublicKeyToAgeRecipient(sshPubkey []byte) (string, error) {
	return sshage.SSHPublicKeyToAgeRecipient(sshPubkey)
}

// ExtractSignerAgeKey extracts the signer's age recipient from an SSH signature.
//
// This is a convenience function that combines ExtractSignerSSHPublicKey and
// SSHPublicKeyToAgeRecipient into a single call.
func ExtractSignerAgeKey(signature string) (string, error) {
	pubkey, err := sshage.ExtractSignerSSHPublicKey(signature)
	if err != nil {
		return "", err
	}
	return sshage.SSHPublicKeyToAgeRecipient(pubkey)
}

// splitRecipients splits a newline-separated string of recipients into a slice.
// Handles .age-recipients format: skips empty lines and # comments.
func splitRecipients(recipients string) []string {
	if recipients == "" {
		return nil
	}
	lines := strings.Split(recipients, "\n")
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			result = append(result, line)
		}
	}
	return result
}
