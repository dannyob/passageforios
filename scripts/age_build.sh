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

git clone --depth 1 --branch "$AGE_VERSION" https://github.com/FiloSottile/age.git "$AGE_PATH"

pushd "$AGE_PATH"
mkdir -p dist

go get golang.org/x/mobile/cmd/gomobile@latest
go get golang.org/x/mobile/cmd/gobind@latest
go build golang.org/x/mobile/cmd/gomobile
go build golang.org/x/mobile/cmd/gobind

./gomobile init
./gomobile bind -tags mobile -target ios -iosversion 13.0 -v -x -ldflags="-s -w" -o dist/Age.xcframework \
  filippo.io/age \
  filippo.io/age/armor
popd

cp -r "$AGE_PATH/dist/Age.xcframework" "$OUTPUT_PATH"
