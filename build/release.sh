#!/bin/bash

if [ -z "$VERSION" ]; then
	echo "Run with \$VERSION set"
	exit 1
fi

dest="$(mktemp -d)"
stage="$dest/edgebit"
arch=$(uname -i)

mkdir -p "$stage/bin"
mkdir -p "$stage/data"

cp ../target/x86_64-unknown-linux-musl/release/edgebit-agent "$stage/bin"
cp syft/* "$stage/bin"
cp syft.yaml "$stage/data"
cp edgebit-agent.service "$stage/data"

cd "$dest"
tarball="$dest/edgebit-${arch}-v${VERSION}.tar.gz"
tar czf "$tarball" edgebit/

echo "$tarball"
