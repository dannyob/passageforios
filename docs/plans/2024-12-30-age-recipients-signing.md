# Age Recipients Signing Verification Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Protect `.age-recipients` from tampering by verifying git commit signatures, using SSH-to-age key derivation to unify signing and encryption keys.

**Architecture:** SSH ed25519 keys serve dual purpose: (1) sign git commits, (2) derive age recipients for encryption. On pull, verify any commit modifying `.age-recipients` is signed by a key whose age-equivalent is already in the trusted recipients list. Trust On First Use (TOFU) for initial setup.

**Tech Stack:** Go (golang.org/x/crypto/ssh, filippo.io/edwards25519), gomobile, Swift/CryptoKit, libgit2 via ObjectiveGit, shell script for CLI verification

---

## Background

### The Attack We're Preventing

```
1. Attacker gets write access to repo
2. Adds their age public key to .age-recipients
3. Signs commit with their own SSH key
4. Victim pulls, re-encrypts secrets
5. Attacker can now decrypt everything
```

### The Defense

```
Rule: Any commit modifying .age-recipients must be signed by an SSH key
      whose age-equivalent is ALREADY in the previous .age-recipients

This means: You can't add yourself - someone already trusted must add you.
```

### Key Conversion (ssh-to-age)

```
SSH ed25519 public key → Edwards25519 point → X25519/Montgomery → bech32("age") → age recipient

Example:
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB6VQIT2tFY4nDfLeMD9rskssM3Tf224pemjYBmZBR9X
    ↓
age1rvuthlzew63h6huxn2xuly3jcgtw6tl665mguuy4alghealzn9dqwz8y7l
```

---

## Bootstrap: Creating the Initial .age-recipients

### The Bootstrap Problem

```
Normal rule: Signer's age key must be in PREVIOUS .age-recipients
Problem: For the first commit, there IS no previous state!
```

### Solution: Self-Consistent Bootstrap

For the **first commit** that creates `.age-recipients`, we use a different rule:

```
Bootstrap rule: Signer's age key must be in THIS .age-recipients
(You can add yourself, but you must include yourself)
```

### Bootstrap Workflow

```bash
# Step 1: Get your age key from your SSH key
$ cat ~/.ssh/id_ed25519.pub | ssh-to-age
age1rvuthlzew63h6huxn2xuly3jcgtw6tl665mguuy4alghealzn9dqwz8y7l

# Step 2: Initialize the password store
$ passage init age1rvuthlzew63h6huxn2xuly3jcgtw6tl665mguuy4alghealzn9dqwz8y7l

# Step 3: Configure git for SSH signing (repo-local)
$ cd ~/.passage
$ git config gpg.format ssh
$ git config user.signingkey ~/.ssh/id_ed25519

# Step 4: Sign the initial commit
$ git add .age-recipients
$ git commit -S -m "Initialize passage store"

# Step 5: Verify bootstrap is valid
$ verify-age-recipients.sh ~/.passage
```

### Adding Team Members

Once bootstrapped, adding someone follows the normal rule:

```bash
# Alice (already in .age-recipients) adds Bob

# Step 1: Bob sends Alice his age key (derived from his SSH key)
# Bob runs: cat ~/.ssh/id_ed25519.pub | ssh-to-age
# Bob sends: age1bobskey...

# Step 2: Alice adds Bob's key
$ echo "age1bobskey..." >> ~/.passage/.age-recipients

# Step 3: Alice signs the commit with HER key
$ git add .age-recipients
$ git commit -S -m "Add Bob to recipients"

# Verification passes because:
#   Alice's SSH key → age1alice... → was in PREVIOUS .age-recipients ✓

# Step 4: Re-encrypt so Bob can access existing secrets
$ passage reencrypt
```

### Verification Rules Summary

| Scenario | Rule |
|----------|------|
| First commit creating `.age-recipients` | Signer's age key must be IN the new `.age-recipients` |
| Subsequent commits modifying `.age-recipients` | Signer's age key must be in PREVIOUS `.age-recipients` |
| Commits not touching `.age-recipients` | No signature required |

---

## Task 0: Shell Script - Pre-Reencrypt Verification

**Files:**
- Create: `scripts/verify-age-recipients.sh`

**Purpose:** Verify `.age-recipients` integrity before running `passage reencrypt`. This script can be used standalone or integrated into a passage wrapper.

**Step 1: Write the verification script**

```bash
#!/usr/bin/env bash
#
# verify-age-recipients.sh - Verify .age-recipients changes are properly signed
#
# Usage: verify-age-recipients.sh [--since COMMIT] [STORE_DIR]
#
# Verifies that all commits modifying .age-recipients are signed by an SSH key
# whose age-equivalent was already in .age-recipients at the time of signing.
#
# Requirements: git, ssh-to-age, ssh-keygen
#
# Exit codes:
#   0 - All changes verified (safe to reencrypt)
#   1 - Verification failed (DO NOT reencrypt)
#   2 - Missing dependencies or invalid arguments

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

die() {
    echo -e "${RED}ERROR: $1${NC}" >&2
    exit "${2:-1}"
}

warn() {
    echo -e "${YELLOW}WARNING: $1${NC}" >&2
}

info() {
    echo -e "${GREEN}✓${NC} $1"
}

# Check dependencies
check_deps() {
    local missing=()
    command -v git >/dev/null || missing+=(git)
    command -v ssh-to-age >/dev/null || missing+=(ssh-to-age)
    command -v ssh-keygen >/dev/null || missing+=(ssh-keygen)

    if [[ ${#missing[@]} -gt 0 ]]; then
        die "Missing dependencies: ${missing[*]}" 2
    fi
}

# Extract SSH public key from a commit signature and convert to age recipient
get_signer_age_key() {
    local commit="$1"

    # Get the signature
    local sig
    sig=$(git cat-file commit "$commit" | sed -n '/^gpgsig /,/-----END SSH SIGNATURE-----/p' | sed 's/^gpgsig //' | sed 's/^ //')

    if [[ -z "$sig" ]]; then
        echo ""
        return
    fi

    # Extract public key from signature and convert to age
    # The signature contains the public key - we need to parse it
    local pubkey
    pubkey=$(echo "$sig" | ssh-keygen -Y find-principals -s /dev/stdin -f <(echo "* ssh-ed25519 *") 2>/dev/null || true)

    # Alternative: parse the signature binary directly
    # For now, we'll use git verify-commit to check validity and extract key
    local key_fp
    key_fp=$(git verify-commit "$commit" 2>&1 | grep -oE 'SHA256:[A-Za-z0-9+/]+' | head -1 || true)

    if [[ -z "$key_fp" ]]; then
        echo ""
        return
    fi

    # We need to get the actual public key from the signature
    # Parse the base64-encoded signature to extract the embedded public key
    local sig_b64
    sig_b64=$(echo "$sig" | grep -v '^-----' | tr -d '\n ')

    # Decode and extract public key (bytes 10-51 contain the pubkey blob for ed25519)
    local pubkey_b64
    pubkey_b64=$(echo "$sig_b64" | base64 -d 2>/dev/null | dd bs=1 skip=10 count=51 2>/dev/null | base64)

    # Convert to SSH authorized_keys format
    echo "ssh-ed25519 $pubkey_b64" | ssh-to-age 2>/dev/null || echo ""
}

# Get .age-recipients content at a specific commit
get_recipients_at_commit() {
    local commit="$1"
    git show "${commit}:.age-recipients" 2>/dev/null | grep -v '^#' | grep -v '^$' || true
}

# Get parent commit
get_parent() {
    local commit="$1"
    git rev-parse "${commit}^" 2>/dev/null || echo ""
}

# Main verification logic
verify_recipients_changes() {
    local store_dir="$1"
    local since_commit="${2:-}"

    cd "$store_dir" || die "Cannot access store directory: $store_dir"

    # Check we're in a git repo
    git rev-parse --git-dir >/dev/null 2>&1 || die "Not a git repository"

    # Check .age-recipients exists
    [[ -f .age-recipients ]] || die ".age-recipients not found"

    # Determine the range of commits to check
    local range
    if [[ -n "$since_commit" ]]; then
        range="${since_commit}..HEAD"
    else
        # Check all commits that touch .age-recipients
        range="HEAD"
    fi

    # Find commits that modified .age-recipients
    local commits
    commits=$(git log --format='%H' --follow -- .age-recipients "$range" 2>/dev/null || true)

    if [[ -z "$commits" ]]; then
        info "No changes to .age-recipients to verify"
        return 0
    fi

    echo "Verifying commits that modified .age-recipients..."
    echo ""

    local failed=0

    while IFS= read -r commit; do
        [[ -z "$commit" ]] && continue

        local short_commit="${commit:0:8}"
        local author
        author=$(git log -1 --format='%an <%ae>' "$commit")
        local date
        date=$(git log -1 --format='%ci' "$commit")

        echo "Checking commit $short_commit ($author, $date)"

        # Check if commit is signed
        if ! git verify-commit "$commit" >/dev/null 2>&1; then
            warn "  Commit $short_commit is NOT signed or signature invalid"
            failed=1
            continue
        fi

        # Get signer's age key
        local signer_age_key
        signer_age_key=$(get_signer_age_key "$commit")

        if [[ -z "$signer_age_key" ]]; then
            warn "  Could not extract signer's age key from $short_commit"
            failed=1
            continue
        fi

        echo "  Signer's age key: ${signer_age_key:0:20}..."

        # Get .age-recipients from PARENT commit (the state before this change)
        local parent
        parent=$(get_parent "$commit")

        local previous_recipients=""
        if [[ -n "$parent" ]]; then
            previous_recipients=$(get_recipients_at_commit "$parent")
        fi

        if [[ -z "$previous_recipients" ]]; then
            # BOOTSTRAP CASE: First .age-recipients commit
            # Rule: Signer's age key must be IN the new .age-recipients (self-consistent)
            local current_recipients
            current_recipients=$(get_recipients_at_commit "$commit")

            if echo "$current_recipients" | grep -qF "$signer_age_key"; then
                info "  Bootstrap commit - signer included themselves ✓"
            else
                echo -e "  ${RED}✗ INVALID BOOTSTRAP: Signer's key is NOT in their own .age-recipients${NC}"
                echo "    A valid bootstrap requires the signer to include their own age key."
                echo "    Signer's age key: $signer_age_key"
                failed=1
            fi
            continue
        fi

        # NORMAL CASE: Check if signer's age key was in PREVIOUS recipients
        if echo "$previous_recipients" | grep -qF "$signer_age_key"; then
            info "  Signer was authorized (key in previous .age-recipients)"
        else
            echo -e "  ${RED}✗ UNAUTHORIZED: Signer's key was NOT in previous .age-recipients${NC}"
            echo "    This commit may be an attempt to add an unauthorized key!"
            echo "    Signer's age key: $signer_age_key"
            failed=1
        fi

        echo ""
    done <<< "$commits"

    return $failed
}

# Parse arguments
SINCE_COMMIT=""
STORE_DIR="${PASSWORD_STORE_DIR:-$HOME/.password-store}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --since)
            SINCE_COMMIT="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [--since COMMIT] [STORE_DIR]"
            echo ""
            echo "Verify .age-recipients changes are properly signed before reencrypting."
            echo ""
            echo "Options:"
            echo "  --since COMMIT   Only check commits after COMMIT"
            echo "  STORE_DIR        Password store directory (default: \$PASSWORD_STORE_DIR or ~/.password-store)"
            echo ""
            echo "Exit codes:"
            echo "  0 - All changes verified (safe to reencrypt)"
            echo "  1 - Verification failed (DO NOT reencrypt)"
            echo "  2 - Missing dependencies or invalid arguments"
            exit 0
            ;;
        *)
            STORE_DIR="$1"
            shift
            ;;
    esac
done

# Main
check_deps

echo "========================================"
echo " .age-recipients Verification"
echo "========================================"
echo ""
echo "Store: $STORE_DIR"
echo ""

if verify_recipients_changes "$STORE_DIR" "$SINCE_COMMIT"; then
    echo ""
    echo -e "${GREEN}========================================"
    echo " ✓ All changes verified - safe to reencrypt"
    echo "========================================${NC}"
    exit 0
else
    echo ""
    echo -e "${RED}========================================"
    echo " ✗ VERIFICATION FAILED"
    echo ""
    echo " DO NOT run 'passage reencrypt' until you"
    echo " manually verify the unauthorized changes!"
    echo "========================================${NC}"
    exit 1
fi
```

**Step 2: Make it executable and test**

```bash
chmod +x scripts/verify-age-recipients.sh
```

**Step 3: Test with our test repo**

```bash
./scripts/verify-age-recipients.sh /tmp/passage-signing-test
```

Expected output:
```
========================================
 .age-recipients Verification
========================================

Store: /tmp/passage-signing-test

Verifying commits that modified .age-recipients...

Checking commit b88929bc (Danny O'Brien <danny@spesh.com>, 2025-12-30)
  Signer's age key: age1rvuthlzew63h6h...
  First .age-recipients commit (TOFU) - trusting

========================================
 ✓ All changes verified - safe to reencrypt
========================================
```

**Step 4: Create a wrapper for passage reencrypt**

```bash
#!/usr/bin/env bash
# safe-reencrypt.sh - Wrapper that verifies before reencrypting

SCRIPT_DIR="$(dirname "$0")"
STORE_DIR="${PASSWORD_STORE_DIR:-$HOME/.password-store}"

# Verify first
if ! "$SCRIPT_DIR/verify-age-recipients.sh" "$STORE_DIR"; then
    echo ""
    echo "Aborting reencrypt due to verification failure."
    echo "If you trust these changes, run: passage reencrypt --force"
    exit 1
fi

# Safe to proceed
echo ""
echo "Verification passed. Running: passage reencrypt $*"
exec passage reencrypt "$@"
```

**Step 5: Commit**

```bash
git add scripts/verify-age-recipients.sh scripts/safe-reencrypt.sh
git commit -m "feat(scripts): add pre-reencrypt verification for .age-recipients"
```

---

## Task 1: Go - SSH Public Key to Age Recipient Conversion

**Files:**
- Create: `scripts/gopenpgp-additions/sshage/convert.go`
- Create: `scripts/gopenpgp-additions/sshage/convert_test.go`

**Step 1: Create directory structure**

```bash
mkdir -p scripts/gopenpgp-additions/sshage
```

**Step 2: Write the failing test**

```go
// scripts/gopenpgp-additions/sshage/convert_test.go
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
	rsaPubkey := []byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... user@host")
	_, err := SSHPublicKeyToAgeRecipient(rsaPubkey)
	if err == nil {
		t.Error("expected error for RSA key, got nil")
	}
}
```

**Step 3: Run test to verify it fails**

```bash
cd scripts/gopenpgp-additions && go test ./sshage/... -v
```

Expected: FAIL with "undefined: SSHPublicKeyToAgeRecipient"

**Step 4: Write minimal implementation**

```go
// scripts/gopenpgp-additions/sshage/convert.go
package sshage

import (
	"crypto/ed25519"
	"errors"
	"strings"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/ssh"
)

var ErrUnsupportedKeyType = errors.New("only ed25519 keys are supported")

// SSHPublicKeyToAgeRecipient converts an SSH ed25519 public key to an age recipient string.
// Input: SSH authorized_keys format (e.g., "ssh-ed25519 AAAA... comment")
// Output: age recipient (e.g., "age1...")
func SSHPublicKeyToAgeRecipient(sshPubkey []byte) (string, error) {
	// Parse SSH public key
	pk, _, _, _, err := ssh.ParseAuthorizedKey(sshPubkey)
	if err != nil {
		return "", err
	}

	if pk.Type() != ssh.KeyAlgoED25519 {
		return "", ErrUnsupportedKeyType
	}

	// Extract raw ed25519 public key bytes
	cryptoPub := pk.(ssh.CryptoPublicKey).CryptoPublicKey()
	ed25519Pub, ok := cryptoPub.(ed25519.PublicKey)
	if !ok {
		return "", errors.New("failed to cast to ed25519.PublicKey")
	}

	// Convert ed25519 (Edwards) to X25519 (Montgomery)
	point, err := new(edwards25519.Point).SetBytes(ed25519Pub)
	if err != nil {
		return "", err
	}
	x25519Pub := point.BytesMontgomery()

	// Bech32 encode with "age" HRP
	return bech32Encode("age", x25519Pub)
}

// bech32 encoding for age format
var bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func bech32Encode(hrp string, data []byte) (string, error) {
	// Convert 8-bit to 5-bit
	var values []byte
	acc := uint32(0)
	bits := uint8(0)
	for _, b := range data {
		acc = (acc << 8) | uint32(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			values = append(values, byte((acc>>bits)&31))
		}
	}
	if bits > 0 {
		values = append(values, byte((acc<<(5-bits))&31))
	}

	// Create checksum
	chk := bech32Checksum(hrp, values)
	values = append(values, chk...)

	// Build result
	var result strings.Builder
	result.WriteString(hrp)
	result.WriteByte('1')
	for _, v := range values {
		result.WriteByte(bech32Charset[v])
	}
	return result.String(), nil
}

func bech32Checksum(hrp string, data []byte) []byte {
	// HRP expansion
	var values []byte
	for _, c := range hrp {
		values = append(values, byte(c>>5))
	}
	values = append(values, 0)
	for _, c := range hrp {
		values = append(values, byte(c&31))
	}
	values = append(values, data...)
	values = append(values, 0, 0, 0, 0, 0, 0)

	// Polymod
	polymod := uint32(1)
	generator := []uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	for _, v := range values {
		top := polymod >> 25
		polymod = ((polymod & 0x1ffffff) << 5) ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (top>>i)&1 == 1 {
				polymod ^= generator[i]
			}
		}
	}
	polymod ^= 1

	// Extract checksum bytes
	result := make([]byte, 6)
	for i := 0; i < 6; i++ {
		result[i] = byte((polymod >> (5 * (5 - i))) & 31)
	}
	return result
}
```

**Step 5: Create go.mod for the package**

```go
// scripts/gopenpgp-additions/go.mod
module github.com/mssun/passforios/sshage

go 1.21

require (
	filippo.io/edwards25519 v1.1.0
	golang.org/x/crypto v0.28.0
)
```

**Step 6: Run test to verify it passes**

```bash
cd scripts/gopenpgp-additions && go mod tidy && go test ./sshage/... -v
```

Expected: PASS

**Step 7: Commit**

```bash
git add scripts/gopenpgp-additions/
git commit -m "feat(sshage): add SSH ed25519 to age recipient conversion"
```

---

## Task 2: Go - SSH Signature Parsing

**Files:**
- Create: `scripts/gopenpgp-additions/sshage/signature.go`
- Modify: `scripts/gopenpgp-additions/sshage/convert_test.go` (add signature tests)

**Step 1: Write the failing test**

```go
// Add to convert_test.go
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
```

**Step 2: Run test to verify it fails**

```bash
cd scripts/gopenpgp-additions && go test ./sshage/... -v
```

Expected: FAIL with "undefined: ParseSSHSignature"

**Step 3: Write implementation**

```go
// scripts/gopenpgp-additions/sshage/signature.go
package sshage

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"

	"golang.org/x/crypto/ssh"
)

// SSHSignature represents a parsed SSH signature
type SSHSignature struct {
	PublicKey     []byte
	KeyType       string
	Namespace     string
	HashAlgorithm string
	Signature     []byte
}

var sshsigMagic = []byte("SSHSIG")

// ParseSSHSignature parses an armored SSH signature
func ParseSSHSignature(armored string) (*SSHSignature, error) {
	// Remove armor
	lines := strings.Split(armored, "\n")
	var b64 strings.Builder
	inSig := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "-----BEGIN SSH SIGNATURE-----" {
			inSig = true
			continue
		}
		if line == "-----END SSH SIGNATURE-----" {
			break
		}
		if inSig && line != "" {
			b64.WriteString(line)
		}
	}

	data, err := base64.StdEncoding.DecodeString(b64.String())
	if err != nil {
		return nil, err
	}

	return parseSSHSignatureBytes(data)
}

func parseSSHSignatureBytes(data []byte) (*SSHSignature, error) {
	r := bytes.NewReader(data)

	// Magic
	magic := make([]byte, 6)
	if _, err := r.Read(magic); err != nil {
		return nil, err
	}
	if !bytes.Equal(magic, sshsigMagic) {
		return nil, errors.New("invalid SSH signature magic")
	}

	// Version
	var version uint32
	if err := binary.Read(r, binary.BigEndian, &version); err != nil {
		return nil, err
	}
	if version != 1 {
		return nil, errors.New("unsupported SSH signature version")
	}

	// Public key blob
	pubkeyBlob, err := readString(r)
	if err != nil {
		return nil, err
	}

	// Parse public key to get type
	pubkey, err := ssh.ParsePublicKey(pubkeyBlob)
	if err != nil {
		return nil, err
	}

	// Namespace
	namespace, err := readString(r)
	if err != nil {
		return nil, err
	}

	// Reserved
	_, err = readString(r)
	if err != nil {
		return nil, err
	}

	// Hash algorithm
	hashAlgo, err := readString(r)
	if err != nil {
		return nil, err
	}

	// Signature blob
	sigBlob, err := readString(r)
	if err != nil {
		return nil, err
	}

	return &SSHSignature{
		PublicKey:     pubkeyBlob,
		KeyType:       pubkey.Type(),
		Namespace:     string(namespace),
		HashAlgorithm: string(hashAlgo),
		Signature:     sigBlob,
	}, nil
}

func readString(r *bytes.Reader) ([]byte, error) {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	data := make([]byte, length)
	if _, err := r.Read(data); err != nil {
		return nil, err
	}
	return data, nil
}

// ExtractSignerSSHPublicKey extracts the signer's public key from an SSH signature
// and returns it in authorized_keys format
func ExtractSignerSSHPublicKey(armored string) ([]byte, error) {
	sig, err := ParseSSHSignature(armored)
	if err != nil {
		return nil, err
	}

	pubkey, err := ssh.ParsePublicKey(sig.PublicKey)
	if err != nil {
		return nil, err
	}

	// Format as authorized_keys line
	return ssh.MarshalAuthorizedKey(pubkey), nil
}
```

**Step 4: Run test to verify it passes**

```bash
cd scripts/gopenpgp-additions && go test ./sshage/... -v
```

Expected: PASS

**Step 5: Commit**

```bash
git add scripts/gopenpgp-additions/sshage/signature.go scripts/gopenpgp-additions/sshage/convert_test.go
git commit -m "feat(sshage): add SSH signature parsing and public key extraction"
```

---

## Task 3: Go - SSH Signature Verification

**Files:**
- Modify: `scripts/gopenpgp-additions/sshage/signature.go` (add verification)
- Modify: `scripts/gopenpgp-additions/sshage/convert_test.go` (add verification tests)

**Step 1: Write the failing test**

```go
// Add to convert_test.go
func TestVerifySSHSignature(t *testing.T) {
	// Signature and signed data from test commit
	armored := `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgHpVAhPa0VjicN8t4wP2uySywzd
N/bbil6aNgGZkFH1cAAAADZ2l0AAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5
AAAAQJ1/uzhCGJADfc0WRMN7SE5/baAkAbqj2bmQh4xGv989iZm0UXDn6Rqy2PDWNJcl7D
nd0VN4HEbSZQuZa8OG5Aw=
-----END SSH SIGNATURE-----`

	// The signed data (commit without gpgsig header)
	signedData := []byte(`tree 656404db43fc2a661d434a7b80d601931f922b28
author Danny O'Brien <danny@spesh.com> 1767127758 -0800
committer Danny O'Brien <danny@spesh.com> 1767127758 -0800

Initial passage setup
`)

	valid, err := VerifySSHSignature(armored, signedData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !valid {
		t.Error("expected valid signature")
	}
}

func TestVerifySSHSignature_InvalidData(t *testing.T) {
	armored := `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgHpVAhPa0VjicN8t4wP2uySywzd
N/bbil6aNgGZkFH1cAAAADZ2l0AAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5
AAAAQJ1/uzhCGJADfc0WRMN7SE5/baAkAbqj2bmQh4xGv989iZm0UXDn6Rqy2PDWNJcl7D
nd0VN4HEbSZQuZa8OG5Aw=
-----END SSH SIGNATURE-----`

	// Tampered data
	signedData := []byte(`tree 656404db43fc2a661d434a7b80d601931f922b28
author Evil Attacker <evil@attacker.com> 1767127758 -0800

Malicious commit
`)

	valid, err := VerifySSHSignature(armored, signedData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid {
		t.Error("expected invalid signature for tampered data")
	}
}
```

**Step 2: Run test to verify it fails**

```bash
cd scripts/gopenpgp-additions && go test ./sshage/... -v
```

Expected: FAIL with "undefined: VerifySSHSignature"

**Step 3: Write implementation**

```go
// Add to signature.go
import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
)

// VerifySSHSignature verifies an SSH signature against signed data
func VerifySSHSignature(armored string, signedData []byte) (bool, error) {
	sig, err := ParseSSHSignature(armored)
	if err != nil {
		return false, err
	}

	if sig.KeyType != ssh.KeyAlgoED25519 {
		return false, ErrUnsupportedKeyType
	}

	// Parse the public key
	pubkey, err := ssh.ParsePublicKey(sig.PublicKey)
	if err != nil {
		return false, err
	}

	cryptoPub := pubkey.(ssh.CryptoPublicKey).CryptoPublicKey()
	ed25519Pub, ok := cryptoPub.(ed25519.PublicKey)
	if !ok {
		return false, errors.New("failed to cast to ed25519.PublicKey")
	}

	// Build the data that was actually signed (per PROTOCOL.sshsig)
	toSign := buildSignedData(sig.Namespace, sig.HashAlgorithm, signedData)

	// Parse signature blob to get raw signature
	sigReader := bytes.NewReader(sig.Signature)
	_, _ = readString(sigReader) // key type (skip)
	rawSig, err := readString(sigReader)
	if err != nil {
		return false, err
	}

	// Verify
	return ed25519.Verify(ed25519Pub, toSign, rawSig), nil
}

func buildSignedData(namespace, hashAlgo string, data []byte) []byte {
	var buf bytes.Buffer

	// Magic preamble
	buf.Write(sshsigMagic)

	// Namespace
	writeString(&buf, []byte(namespace))

	// Reserved (empty)
	writeString(&buf, []byte{})

	// Hash algorithm
	writeString(&buf, []byte(hashAlgo))

	// Hash of the message
	var hash []byte
	switch hashAlgo {
	case "sha512":
		h := sha512.Sum512(data)
		hash = h[:]
	default:
		h := sha256.Sum256(data)
		hash = h[:]
	}
	writeString(&buf, hash)

	return buf.Bytes()
}

func writeString(buf *bytes.Buffer, data []byte) {
	binary.Write(buf, binary.BigEndian, uint32(len(data)))
	buf.Write(data)
}
```

**Step 4: Run test to verify it passes**

```bash
cd scripts/gopenpgp-additions && go test ./sshage/... -v
```

Expected: PASS

**Step 5: Commit**

```bash
git add scripts/gopenpgp-additions/sshage/signature.go scripts/gopenpgp-additions/sshage/convert_test.go
git commit -m "feat(sshage): add SSH signature verification"
```

---

## Tasks 4-11: iOS Implementation

(Remaining tasks for Go mobile bindings and Swift integration - see above for details)

---

## Summary

| Task | Component | Effort |
|------|-----------|--------|
| 0 | Shell: Pre-reencrypt verification script | 30 min |
| 1 | Go: SSH to age conversion | 30 min |
| 2 | Go: SSH signature parsing | 30 min |
| 3 | Go: Signature verification | 30 min |
| 4 | Go: High-level API | 20 min |
| 5 | Go: Gomobile bindings | 15 min |
| 6 | Build: Integrate into gopenpgp | 30 min |
| 7 | Swift: Signature extraction | 30 min |
| 8 | Swift: Trust management | 30 min |
| 9 | Integration: Verify on pull | 45 min |
| 10 | UI: Trust initialization | 30 min |
| 11 | UI: Failure alerts | 20 min |
| **Total** | | **~5.5 hours** |

## Testing Checklist

### Shell Script Tests
- [ ] Valid bootstrap: signer includes themselves in initial `.age-recipients`
- [ ] Invalid bootstrap: signer NOT in their own `.age-recipients` (should fail)
- [ ] Valid addition: authorized signer adds new recipient
- [ ] Unauthorized addition: non-authorized signer adds recipient (should fail)
- [ ] Unsigned commit modifying `.age-recipients` (should fail)
- [ ] Commits not touching `.age-recipients` (should skip)

### Go Unit Tests
- [ ] SSH → age conversion (known test vector)
- [ ] SSH → age rejects non-ed25519 keys
- [ ] Signature parsing extracts correct fields
- [ ] Signature verification (valid signature)
- [ ] Signature verification (tampered data - should fail)
- [ ] VerifyRecipientsChange with authorized signer
- [ ] VerifyRecipientsChange with unauthorized signer (should fail)

### iOS Integration Tests
- [ ] Trust manager stores/retrieves state correctly
- [ ] First clone initializes trust (TOFU)
- [ ] Pull with valid signed change updates trust
- [ ] Pull with unsigned change shows warning
- [ ] Pull with unauthorized signer shows warning
- [ ] UI allows "Trust Anyway" override
- [ ] UI allows "Revert" to last verified state

### End-to-End Manual Tests
```bash
# Test 1: Valid bootstrap
$ mkdir /tmp/test-passage && cd /tmp/test-passage && git init
$ git config gpg.format ssh && git config user.signingkey ~/.ssh/id_ed25519
$ echo "$(cat ~/.ssh/id_ed25519.pub | ssh-to-age)" > .age-recipients
$ git add . && git commit -S -m "Bootstrap"
$ verify-age-recipients.sh .   # Should PASS

# Test 2: Invalid bootstrap (signer not in recipients)
$ mkdir /tmp/test-bad && cd /tmp/test-bad && git init
$ git config gpg.format ssh && git config user.signingkey ~/.ssh/id_ed25519
$ echo "age1someoneelse..." > .age-recipients  # NOT signer's key
$ git add . && git commit -S -m "Bad bootstrap"
$ verify-age-recipients.sh .   # Should FAIL

# Test 3: Unauthorized modification
$ cd /tmp/test-passage
$ echo "age1attackerkey..." >> .age-recipients
# (sign with a DIFFERENT key not in recipients)
$ verify-age-recipients.sh .   # Should FAIL
```
