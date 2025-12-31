#!/bin/bash

# Unified build script for crypto frameworks (Gopenpgp + Age)
# Combines both into a single xcframework to avoid Go runtime conflicts.
#
# This builds from within the gopenpgp fork (which has mobile bindings)
# and adds age as a dependency.

set -euox pipefail

GOPENPGP_VERSION="v2.8.1-passforios"
AGE_VERSION="v1.2.0"

export GOPATH="$(pwd)/go"
export PATH="$PATH:$GOPATH/bin"

OUTPUT_PATH="go/dist"
CHECKOUT_PATH="go/checkout"
GOPENPGP_PATH="$CHECKOUT_PATH/gopenpgp-combined"

mkdir -p "$OUTPUT_PATH"
mkdir -p "$CHECKOUT_PATH"

# Handle existing checkout
if [[ -d "$GOPENPGP_PATH" ]]; then
  if [[ -d "$GOPENPGP_PATH/.git" ]]; then
    echo "gopenpgp already checked out at $GOPENPGP_PATH"
    if [[ "${1:-}" == "--clean" ]]; then
      echo "Removing existing checkout (--clean specified)"
      \rm -rf "$GOPENPGP_PATH"
      git clone --depth 1 --branch "$GOPENPGP_VERSION" https://github.com/mssun/gopenpgp.git "$GOPENPGP_PATH"
    else
      echo "Updating existing checkout to $GOPENPGP_VERSION"
      pushd "$GOPENPGP_PATH"
      git fetch --depth 1 origin tag "$GOPENPGP_VERSION"
      git checkout "$GOPENPGP_VERSION"
      popd
    fi
  else
    echo "Error: $GOPENPGP_PATH exists but is not a git repository"
    echo "Remove it manually or run with --clean"
    exit 1
  fi
else
  git clone --depth 1 --branch "$GOPENPGP_VERSION" https://github.com/mssun/gopenpgp.git "$GOPENPGP_PATH"
fi

pushd "$GOPENPGP_PATH"

# Add age dependency
go get filippo.io/age@$AGE_VERSION

# Copy sshage module for trust verification
SSHAGE_SRC="$(dirs -l +1)/scripts/gopenpgp-additions"
if [[ -d "$SSHAGE_SRC" ]]; then
  echo "Copying sshage module from $SSHAGE_SRC"
  cp -r "$SSHAGE_SRC" "./sshage-module"
  # Remove nested go.mod from mobile package (it becomes a subpackage)
  rm -f ./sshage-module/sshage/mobile/go.mod ./sshage-module/sshage/mobile/go.sum

  # Add replace directive for sshage
  cat >> go.mod <<'GOMOD'

replace github.com/mssun/passforios/sshage => ./sshage-module
GOMOD
fi

# Create agewrap package with gomobile-compatible wrappers
mkdir -p agewrap
cat > agewrap/agewrap.go << 'GOEOF'
// Package agewrap provides gomobile-compatible wrappers for age encryption.
package agewrap

import (
	"bytes"
	"io"

	"filippo.io/age"
)

// DecryptWithIdentity decrypts data encrypted to the given X25519 identity.
func DecryptWithIdentity(ciphertext []byte, identity *age.X25519Identity) ([]byte, error) {
	reader, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(reader)
}

// EncryptToRecipient encrypts data to the given X25519 recipient.
func EncryptToRecipient(plaintext []byte, recipient *age.X25519Recipient) ([]byte, error) {
	var buf bytes.Buffer
	writer, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return nil, err
	}
	if _, err := writer.Write(plaintext); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
GOEOF

go mod tidy

mkdir -p dist

# Install gomobile tools
go get golang.org/x/mobile/cmd/gomobile@latest
go get golang.org/x/mobile/cmd/gobind@latest
go build golang.org/x/mobile/cmd/gomobile
go build golang.org/x/mobile/cmd/gobind

./gomobile init

# Add sshage dependencies if module exists
if [[ -d "./sshage-module" ]]; then
  go get github.com/mssun/passforios/sshage
  go get github.com/mssun/passforios/sshage/sshage
  # Ensure sshage is in require (go mod tidy might remove it if nothing imports it yet)
  if ! grep -q "^require github.com/mssun/passforios/sshage" go.mod; then
    echo 'require github.com/mssun/passforios/sshage v0.0.0' >> go.mod
  fi
fi

go mod tidy
# Re-add dependencies that go mod tidy might have removed
if [[ -d "./sshage-module" ]]; then
  if ! grep -q "^require github.com/mssun/passforios/sshage" go.mod; then
    echo 'require github.com/mssun/passforios/sshage v0.0.0' >> go.mod
  fi
fi
# golang.org/x/mobile must be in go.mod for gomobile bind to work
go get golang.org/x/mobile
go mod download all

# Build combined framework with Gopenpgp, Age, and sshage
PACKAGES=(
  github.com/ProtonMail/gopenpgp/v2/crypto
  github.com/ProtonMail/gopenpgp/v2/armor
  github.com/ProtonMail/gopenpgp/v2/constants
  github.com/ProtonMail/gopenpgp/v2/models
  github.com/ProtonMail/gopenpgp/v2/subtle
  github.com/ProtonMail/gopenpgp/v2/helper
  filippo.io/age
  filippo.io/age/armor
  github.com/ProtonMail/gopenpgp/v2/agewrap
)

# Add sshage/mobile if available
if [[ -d "./sshage-module" ]]; then
  PACKAGES+=(github.com/mssun/passforios/sshage/sshage/mobile)
fi

./gomobile bind -tags mobile -target ios -iosversion 13.0 -v -x -ldflags="-s -w" -o dist/Crypto.xcframework \
  "${PACKAGES[@]}"

popd

# Copy to output
cp -r "$GOPENPGP_PATH/dist/Crypto.xcframework" "$OUTPUT_PATH"

echo ""
echo "Built combined Crypto.xcframework at $OUTPUT_PATH/Crypto.xcframework"
echo ""
echo "IMPORTANT: Update your Xcode project to:"
echo "  1. Remove Gopenpgp.xcframework and Age.xcframework references"
echo "  2. Add Crypto.xcframework instead"
echo "  3. Update imports from 'import Gopenpgp' to 'import Crypto'"
echo "  4. Update imports from 'import Age' to 'import Crypto'"
