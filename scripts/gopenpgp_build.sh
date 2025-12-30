#!/bin/bash

set -euox pipefail

GOPENPGP_VERSION="v2.8.1-passforios"

export GOPATH="$(pwd)/go"
export PATH="$PATH:$GOPATH/bin"

OUTPUT_PATH="go/dist"
CHECKOUT_PATH="go/checkout"
GOPENPGP_PATH="$CHECKOUT_PATH/gopenpgp"

mkdir -p "$OUTPUT_PATH"
mkdir -p "$CHECKOUT_PATH"

git clone --depth 1 --branch "$GOPENPGP_VERSION" https://github.com/mssun/gopenpgp.git "$GOPENPGP_PATH"

# Copy sshage module into gopenpgp checkout
# The sshage module root is gopenpgp-additions/, containing go.mod and sshage/ subpackage
SSHAGE_SRC="$(pwd)/scripts/gopenpgp-additions"
SSHAGE_DEST="$GOPENPGP_PATH/sshage-module"
cp -r "$SSHAGE_SRC" "$SSHAGE_DEST"

# Remove the nested go.mod in mobile/ to make it part of the parent module
# This allows gomobile to bind the mobile package as part of the sshage module
rm -f "$SSHAGE_DEST/sshage/mobile/go.mod" "$SSHAGE_DEST/sshage/mobile/go.sum"

pushd "$GOPENPGP_PATH"

# Add sshage to go.mod with replace directive pointing to local copy
cat >> go.mod <<'GOMOD'

replace github.com/mssun/passforios/sshage => ./sshage-module
GOMOD

# Run go mod tidy first to update existing dependencies
go mod tidy

# Add sshage as a dependency after go mod tidy (so it doesn't get removed)
# Then fetch the sshage subpackage to ensure its dependencies are in go.sum
go get github.com/mssun/passforios/sshage
go get github.com/mssun/passforios/sshage/sshage

# Ensure all dependencies are downloaded (go.sum gets updated by tidy/get)
go mod download all
mkdir -p dist
go get golang.org/x/mobile/cmd/gomobile@latest
go get golang.org/x/mobile/cmd/gobind@latest
go build golang.org/x/mobile/cmd/gomobile
go build golang.org/x/mobile/cmd/gobind
go mod download github.com/ProtonMail/go-crypto
./gomobile init
./gomobile bind -tags mobile -target ios -iosversion 13.0 -v -x -ldflags="-s -w" -o dist/Gopenpgp.xcframework \
  github.com/ProtonMail/gopenpgp/v2/crypto \
  github.com/ProtonMail/gopenpgp/v2/armor \
  github.com/ProtonMail/gopenpgp/v2/constants \
  github.com/ProtonMail/gopenpgp/v2/models \
  github.com/ProtonMail/gopenpgp/v2/subtle \
  github.com/ProtonMail/gopenpgp/v2/helper \
  github.com/mssun/passforios/sshage/sshage/mobile
popd

cp -r "$GOPENPGP_PATH/dist/Gopenpgp.xcframework" "$OUTPUT_PATH"

