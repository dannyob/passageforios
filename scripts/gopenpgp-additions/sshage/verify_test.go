// Package sshage provides high-level verification for .age-recipients changes.
package sshage

import (
	"strings"
	"testing"
)

// Test signature from convert_test.go - this signature's public key converts to:
// age1rvuthlzew63h6huxn2xuly3jcgtw6tl665mguuy4alghealzn9dqwz8y7l
var testSignature = `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgHpVAhPa0VjicN8t4wP2uySywzd
N/bbil6aNgGZkFH1cAAAADZ2l0AAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5
AAAAQJ1/uzhCGJADfc0WRMN7SE5/baAkAbqj2bmQh4xGv989iZm0UXDn6Rqy2PDWNJcl7D
nd0VN4HEbSZQuZa8OG5Aw=
-----END SSH SIGNATURE-----`

// The age recipient that corresponds to the test signature's public key
const testSignerAgeKey = "age1rvuthlzew63h6huxn2xuly3jcgtw6tl665mguuy4alghealzn9dqwz8y7l"

// Some dummy signed data (not cryptographically valid for this signature, but
// we can test with verifySignature=false)
var dummySignedData = []byte("tree abc123\nauthor test\n\ntest commit\n")

func TestVerifyRecipientsChange_Authorized(t *testing.T) {
	// Signer's age key is in the authorized list
	authorizedRecipients := []string{
		"age1someotherkey123456789012345678901234567890123456789012345",
		testSignerAgeKey, // The signer IS authorized
		"age1anotherkey123456789012345678901234567890123456789012345678",
	}

	signerKey, authorized, err := VerifyRecipientsChange(
		testSignature,
		dummySignedData,
		authorizedRecipients,
		false, // Don't verify signature cryptographically
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if signerKey != testSignerAgeKey {
		t.Errorf("got signer key %s, want %s", signerKey, testSignerAgeKey)
	}
	if !authorized {
		t.Error("expected authorized=true for authorized signer")
	}
}

func TestVerifyRecipientsChange_Unauthorized(t *testing.T) {
	// Signer's age key is NOT in the authorized list
	authorizedRecipients := []string{
		"age1someotherkey123456789012345678901234567890123456789012345",
		"age1anotherkey123456789012345678901234567890123456789012345678",
	}

	signerKey, authorized, err := VerifyRecipientsChange(
		testSignature,
		dummySignedData,
		authorizedRecipients,
		false,
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if signerKey != testSignerAgeKey {
		t.Errorf("got signer key %s, want %s", signerKey, testSignerAgeKey)
	}
	if authorized {
		t.Error("expected authorized=false for unauthorized signer")
	}
}

func TestVerifyRecipientsChange_EmptyAuthorizedList(t *testing.T) {
	// Empty authorized list means no one is authorized
	signerKey, authorized, err := VerifyRecipientsChange(
		testSignature,
		dummySignedData,
		[]string{},
		false,
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if signerKey != testSignerAgeKey {
		t.Errorf("got signer key %s, want %s", signerKey, testSignerAgeKey)
	}
	if authorized {
		t.Error("expected authorized=false for empty authorized list")
	}
}

func TestVerifyRecipientsChange_InvalidSignature(t *testing.T) {
	invalidSignature := "not a valid signature"

	_, _, err := VerifyRecipientsChange(
		invalidSignature,
		dummySignedData,
		[]string{testSignerAgeKey},
		false,
	)

	if err == nil {
		t.Error("expected error for invalid signature")
	}
}

func TestVerifyRecipientsChange_WithCryptoVerification(t *testing.T) {
	// This test uses the signature from convert_test.go that has matching data
	// Signature created by: git commit -S -m "Test signed commit"
	signatureWithValidData := `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgemrT5mkFBsqMQpv+PFLyV1i+Bs
zB353QhGPCCvuX/ewAAAADZ2l0AAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5
AAAAQOfxOeFKLQHK0tneuTrs7MSCdiRMtsigwwZ79o3ODBkdX9WZRv9UY8YXfoNERb0/g+
jm2lbGXzCrVr4Mh57fiww=
-----END SSH SIGNATURE-----`

	// The exact data that was signed
	validSignedData := []byte("tree aaa96ced2d9a1c8e72c56b253a0e2fe78393feb7\n" +
		"author Test User <test@test.com> 1767136957 -0800\n" +
		"committer Test User <test@test.com> 1767136957 -0800\n" +
		"\n" +
		"Test signed commit\n")

	// First extract the age key from this different signature
	pubkey, err := ExtractSignerSSHPublicKey(signatureWithValidData)
	if err != nil {
		t.Fatalf("failed to extract public key: %v", err)
	}
	ageKey, err := SSHPublicKeyToAgeRecipient(pubkey)
	if err != nil {
		t.Fatalf("failed to convert to age: %v", err)
	}

	// Authorize this signer
	authorizedRecipients := []string{ageKey}

	signerKey, authorized, err := VerifyRecipientsChange(
		signatureWithValidData,
		validSignedData,
		authorizedRecipients,
		true, // DO verify signature cryptographically
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if signerKey != ageKey {
		t.Errorf("got signer key %s, want %s", signerKey, ageKey)
	}
	if !authorized {
		t.Error("expected authorized=true")
	}
}

func TestVerifyRecipientsChange_CryptoVerificationFails(t *testing.T) {
	// Use testSignature but with data that doesn't match
	// When verifySignature=true, this should fail
	authorizedRecipients := []string{testSignerAgeKey}

	_, _, err := VerifyRecipientsChange(
		testSignature,
		[]byte("wrong data that wasn't signed"),
		authorizedRecipients,
		true, // Verify signature cryptographically
	)

	if err == nil {
		t.Error("expected error for cryptographic verification failure")
	}
	if !strings.Contains(err.Error(), "signature verification failed") {
		t.Errorf("expected 'signature verification failed' error, got: %v", err)
	}
}

func TestIsBootstrapValid_ValidBootstrap(t *testing.T) {
	// The signer's key IS in their own new recipients list
	newRecipients := []string{
		"age1someotherkey123456789012345678901234567890123456789012345",
		testSignerAgeKey, // Signer includes themselves
		"age1anotherkey123456789012345678901234567890123456789012345678",
	}

	signerKey, valid, err := IsBootstrapValid(
		testSignature,
		dummySignedData,
		newRecipients,
		false,
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if signerKey != testSignerAgeKey {
		t.Errorf("got signer key %s, want %s", signerKey, testSignerAgeKey)
	}
	if !valid {
		t.Error("expected valid=true when signer is in new recipients")
	}
}

func TestIsBootstrapValid_InvalidBootstrap(t *testing.T) {
	// The signer's key is NOT in their own new recipients list
	// This is suspicious - why would someone create a file that doesn't include themselves?
	newRecipients := []string{
		"age1someotherkey123456789012345678901234567890123456789012345",
		"age1anotherkey123456789012345678901234567890123456789012345678",
	}

	signerKey, valid, err := IsBootstrapValid(
		testSignature,
		dummySignedData,
		newRecipients,
		false,
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if signerKey != testSignerAgeKey {
		t.Errorf("got signer key %s, want %s", signerKey, testSignerAgeKey)
	}
	if valid {
		t.Error("expected valid=false when signer is not in new recipients")
	}
}

func TestIsBootstrapValid_EmptyRecipients(t *testing.T) {
	// Empty recipients list - bootstrap is invalid
	signerKey, valid, err := IsBootstrapValid(
		testSignature,
		dummySignedData,
		[]string{},
		false,
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if signerKey != testSignerAgeKey {
		t.Errorf("got signer key %s, want %s", signerKey, testSignerAgeKey)
	}
	if valid {
		t.Error("expected valid=false for empty recipients")
	}
}

func TestIsBootstrapValid_InvalidSignature(t *testing.T) {
	invalidSignature := "not valid"

	_, _, err := IsBootstrapValid(
		invalidSignature,
		dummySignedData,
		[]string{testSignerAgeKey},
		false,
	)

	if err == nil {
		t.Error("expected error for invalid signature")
	}
}

func TestIsBootstrapValid_WithCryptoVerification(t *testing.T) {
	// Similar to TestVerifyRecipientsChange_WithCryptoVerification
	signatureWithValidData := `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgemrT5mkFBsqMQpv+PFLyV1i+Bs
zB353QhGPCCvuX/ewAAAADZ2l0AAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5
AAAAQOfxOeFKLQHK0tneuTrs7MSCdiRMtsigwwZ79o3ODBkdX9WZRv9UY8YXfoNERb0/g+
jm2lbGXzCrVr4Mh57fiww=
-----END SSH SIGNATURE-----`

	validSignedData := []byte("tree aaa96ced2d9a1c8e72c56b253a0e2fe78393feb7\n" +
		"author Test User <test@test.com> 1767136957 -0800\n" +
		"committer Test User <test@test.com> 1767136957 -0800\n" +
		"\n" +
		"Test signed commit\n")

	// Extract the age key
	pubkey, err := ExtractSignerSSHPublicKey(signatureWithValidData)
	if err != nil {
		t.Fatalf("failed to extract public key: %v", err)
	}
	ageKey, err := SSHPublicKeyToAgeRecipient(pubkey)
	if err != nil {
		t.Fatalf("failed to convert to age: %v", err)
	}

	// Include signer in new recipients
	newRecipients := []string{ageKey}

	signerKey, valid, err := IsBootstrapValid(
		signatureWithValidData,
		validSignedData,
		newRecipients,
		true,
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if signerKey != ageKey {
		t.Errorf("got signer key %s, want %s", signerKey, ageKey)
	}
	if !valid {
		t.Error("expected valid=true")
	}
}

// Test that whitespace/formatting variations in age keys are handled
func TestVerifyRecipientsChange_WhitespaceHandling(t *testing.T) {
	// Recipients list with whitespace variations
	authorizedRecipients := []string{
		"  " + testSignerAgeKey + "  ", // Leading and trailing spaces
	}

	signerKey, authorized, err := VerifyRecipientsChange(
		testSignature,
		dummySignedData,
		authorizedRecipients,
		false,
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if signerKey != testSignerAgeKey {
		t.Errorf("got signer key %s, want %s", signerKey, testSignerAgeKey)
	}
	if !authorized {
		t.Error("expected authorized=true even with whitespace in authorized list")
	}
}

// Test case sensitivity (age keys are lowercase)
func TestVerifyRecipientsChange_CaseSensitivity(t *testing.T) {
	// Uppercase version of the key - should NOT match since age keys are case-sensitive
	uppercaseKey := strings.ToUpper(testSignerAgeKey)
	authorizedRecipients := []string{uppercaseKey}

	signerKey, authorized, err := VerifyRecipientsChange(
		testSignature,
		dummySignedData,
		authorizedRecipients,
		false,
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if signerKey != testSignerAgeKey {
		t.Errorf("got signer key %s, want %s", signerKey, testSignerAgeKey)
	}
	// Age keys are bech32 encoded and are case-insensitive per bech32 spec,
	// but the canonical form is lowercase. We should handle this gracefully.
	// For safety, let's NOT match - the stored keys should be canonical lowercase.
	if authorized {
		t.Error("expected authorized=false for case mismatch (enforcing canonical lowercase)")
	}
}
