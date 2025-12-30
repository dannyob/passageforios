// Package sshage provides conversion between SSH ed25519 public keys and age recipients.
package sshage

import (
	"testing"
)

func TestSSHPublicKeyToAgeRecipient(t *testing.T) {
	// Known conversion from ssh-to-age tool
	sshPubkey := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB6VQIT2tFY4nDfLeMD9rskssM3Tf224pemjYBmZBR9X danny@yacht")
	expectedAge := "age1rvuthlzew63h6huxn2xuly3jcgtw6tl665mguuy4alghealzn9dqwz8y7l"

	result, err := SSHPublicKeyToAgeRecipient(sshPubkey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != expectedAge {
		t.Errorf("got %s, want %s", result, expectedAge)
	}
}

func TestSSHPublicKeyToAgeRecipient_RejectsRSA(t *testing.T) {
	rsaPubkey := []byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC7pTm... user@host")
	_, err := SSHPublicKeyToAgeRecipient(rsaPubkey)
	if err == nil {
		t.Error("expected error for RSA key, got nil")
	}
}

func TestSSHPublicKeyToAgeRecipient_RejectsECDSA(t *testing.T) {
	ecdsaPubkey := []byte("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYA... user@host")
	_, err := SSHPublicKeyToAgeRecipient(ecdsaPubkey)
	if err == nil {
		t.Error("expected error for ECDSA key, got nil")
	}
}

func TestSSHPublicKeyToAgeRecipient_InvalidFormat(t *testing.T) {
	invalidPubkey := []byte("not a valid ssh key")
	_, err := SSHPublicKeyToAgeRecipient(invalidPubkey)
	if err == nil {
		t.Error("expected error for invalid key, got nil")
	}
}

func TestSSHPublicKeyToAgeRecipient_EmptyInput(t *testing.T) {
	_, err := SSHPublicKeyToAgeRecipient([]byte{})
	if err == nil {
		t.Error("expected error for empty input, got nil")
	}
}

func TestParseSSHSignature(t *testing.T) {
	// Real signature from test commit
	armored := `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgHpVAhPa0VjicN8t4wP2uySywzd
N/bbil6aNgGZkFH1cAAAADZ2l0AAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5
AAAAQJ1/uzhCGJADfc0WRMN7SE5/baAkAbqj2bmQh4xGv989iZm0UXDn6Rqy2PDWNJcl7D
nd0VN4HEbSZQuZa8OG5Aw=
-----END SSH SIGNATURE-----`

	sig, err := ParseSSHSignature(armored)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if sig.KeyType != "ssh-ed25519" {
		t.Errorf("got key type %s, want ssh-ed25519", sig.KeyType)
	}
	if sig.Namespace != "git" {
		t.Errorf("got namespace %s, want git", sig.Namespace)
	}
	if sig.HashAlgorithm != "sha512" {
		t.Errorf("got hash %s, want sha512", sig.HashAlgorithm)
	}
}

func TestExtractSignerPublicKey(t *testing.T) {
	armored := `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgHpVAhPa0VjicN8t4wP2uySywzd
N/bbil6aNgGZkFH1cAAAADZ2l0AAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5
AAAAQJ1/uzhCGJADfc0WRMN7SE5/baAkAbqj2bmQh4xGv989iZm0UXDn6Rqy2PDWNJcl7D
nd0VN4HEbSZQuZa8OG5Aw=
-----END SSH SIGNATURE-----`

	pubkey, err := ExtractSignerSSHPublicKey(armored)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Convert to age and check it matches expected
	ageRecipient, err := SSHPublicKeyToAgeRecipient(pubkey)
	if err != nil {
		t.Fatalf("unexpected error converting to age: %v", err)
	}

	expected := "age1rvuthlzew63h6huxn2xuly3jcgtw6tl665mguuy4alghealzn9dqwz8y7l"
	if ageRecipient != expected {
		t.Errorf("got %s, want %s", ageRecipient, expected)
	}
}

func TestVerifySSHSignature(t *testing.T) {
	// Signature from a test git commit signed with ssh-ed25519
	// The signature was created by: git commit -S -m "Test signed commit"
	// with gpg.format=ssh and a known ed25519 key
	armored := `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgemrT5mkFBsqMQpv+PFLyV1i+Bs
zB353QhGPCCvuX/ewAAAADZ2l0AAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5
AAAAQOfxOeFKLQHK0tneuTrs7MSCdiRMtsigwwZ79o3ODBkdX9WZRv9UY8YXfoNERb0/g+
jm2lbGXzCrVr4Mh57fiww=
-----END SSH SIGNATURE-----`

	// The signed data (commit object content without gpgsig header)
	// This must include the trailing newline to match what git signs
	signedData := []byte("tree aaa96ced2d9a1c8e72c56b253a0e2fe78393feb7\n" +
		"author Test User <test@test.com> 1767136957 -0800\n" +
		"committer Test User <test@test.com> 1767136957 -0800\n" +
		"\n" +
		"Test signed commit\n")

	valid, err := VerifySSHSignature(armored, signedData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !valid {
		t.Error("expected valid signature")
	}
}

func TestVerifySSHSignature_InvalidData(t *testing.T) {
	// Same signature as above
	armored := `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgemrT5mkFBsqMQpv+PFLyV1i+Bs
zB353QhGPCCvuX/ewAAAADZ2l0AAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5
AAAAQOfxOeFKLQHK0tneuTrs7MSCdiRMtsigwwZ79o3ODBkdX9WZRv9UY8YXfoNERb0/g+
jm2lbGXzCrVr4Mh57fiww=
-----END SSH SIGNATURE-----`

	// Tampered data - different author and message
	signedData := []byte("tree aaa96ced2d9a1c8e72c56b253a0e2fe78393feb7\n" +
		"author Evil Attacker <evil@attacker.com> 1767136957 -0800\n" +
		"\n" +
		"Malicious commit\n")

	valid, err := VerifySSHSignature(armored, signedData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid {
		t.Error("expected invalid signature for tampered data")
	}
}

func TestVerifySSHSignature_SubtleTampering(t *testing.T) {
	// Same signature
	armored := `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgemrT5mkFBsqMQpv+PFLyV1i+Bs
zB353QhGPCCvuX/ewAAAADZ2l0AAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5
AAAAQOfxOeFKLQHK0tneuTrs7MSCdiRMtsigwwZ79o3ODBkdX9WZRv9UY8YXfoNERb0/g+
jm2lbGXzCrVr4Mh57fiww=
-----END SSH SIGNATURE-----`

	// Single character change in tree hash
	signedData := []byte("tree baa96ced2d9a1c8e72c56b253a0e2fe78393feb7\n" +
		"author Test User <test@test.com> 1767136957 -0800\n" +
		"committer Test User <test@test.com> 1767136957 -0800\n" +
		"\n" +
		"Test signed commit\n")

	valid, err := VerifySSHSignature(armored, signedData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid {
		t.Error("expected invalid signature for subtly tampered data")
	}
}
