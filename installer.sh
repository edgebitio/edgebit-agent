#!/bin/sh

EDGEBIT_URL=https://app.edgebit.io
TARBALL_URL=
PREFIX=/opt/edgebit

cd "$PREFIX"

# Download agent and syft
echo "Downloading agent"
mkdir -p "$PREFIX"
curl "$TARBALL_URL" | tar xz

# Start the agent
echo "Starting agent"
RUST_LOG=info "$PREFIX/agentd"
