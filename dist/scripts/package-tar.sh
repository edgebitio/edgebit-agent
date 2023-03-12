#!/bin/bash

DEST=$(realpath "$1")

stage="$(mktemp -d)/edgebit"
mkdir -p "$stage"

cp "../target/$ARCH-unknown-linux-musl/release/edgebit-agent" "$stage"
cp -r syft "$stage"
cp syft.yaml "$stage"
cp edgebit-agent.service "$stage"

cd "$stage"/..
tar czf "$DEST" edgebit/
