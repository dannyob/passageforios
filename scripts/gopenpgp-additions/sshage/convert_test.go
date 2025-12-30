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
