#!/bin/bash

set -euox pipefail

AGE_VERSION="v1.2.0"

export GOPATH="$(pwd)/go"
export PATH="$PATH:$GOPATH/bin"

OUTPUT_PATH="go/dist"
CHECKOUT_PATH="go/checkout"
AGE_PATH="$CHECKOUT_PATH/age"

mkdir -p "$OUTPUT_PATH"
mkdir -p "$CHECKOUT_PATH"

if [[ -d "$AGE_PATH" ]]; then
  if [[ -d "$AGE_PATH/.git" ]]; then
    echo "age already checked out at $AGE_PATH"
    if [[ "${1:-}" == "--clean" ]]; then
      echo "Removing existing checkout (--clean specified)"
      \rm -rf "$AGE_PATH"
      git clone --depth 1 --branch "$AGE_VERSION" https://github.com/FiloSottile/age.git "$AGE_PATH"
    else
      echo "Updating existing checkout to $AGE_VERSION"
      pushd "$AGE_PATH"
      git fetch --depth 1 origin tag "$AGE_VERSION"
      git checkout "$AGE_VERSION"
      popd
    fi
  else
    echo "Error: $AGE_PATH exists but is not a git repository"
    echo "Remove it manually or run with --clean"
    exit 1
  fi
else
  git clone --depth 1 --branch "$AGE_VERSION" https://github.com/FiloSottile/age.git "$AGE_PATH"
fi

pushd "$AGE_PATH"
mkdir -p dist

go get golang.org/x/mobile/cmd/gomobile@latest
go get golang.org/x/mobile/cmd/gobind@latest
go build golang.org/x/mobile/cmd/gomobile
go build golang.org/x/mobile/cmd/gobind

./gomobile init

# Create wrapper subpackage inside age module
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

./gomobile bind -tags mobile -target ios -iosversion 13.0 -v -x -ldflags="-s -w" -o dist/Age.xcframework \
  filippo.io/age \
  filippo.io/age/armor \
  filippo.io/age/agewrap
popd

cp -r "$AGE_PATH/dist/Age.xcframework" "$OUTPUT_PATH"
