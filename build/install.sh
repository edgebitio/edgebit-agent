#!/bin/sh -e

arch=$(uname -i)

: "${VERSION:=0.0.7}"
: "${EDGEBIT_URL:=https://app.edgebit.io}"
: "${TARBALL_URL:=https://install.edgebit.io/edgebit-${arch}-v${VERSION}.tar.gz}"
: "${PREFIX:=/opt}"

export EDGEBIT_URL

die() {
	echo "Error: $1" >> /dev/stderr
	exit 1
}

systemd_install() {
	if [ "$has_systemd" -ne "1" ]; then
		die "systemd required for persistent install"
	fi

	echo "Installing files"
	install "${PREFIX}/edgebit/data/edgebit-agent.service" /usr/lib/systemd/system/

	mkdir -p /etc/edgebit
	echo "EDGEBIT_ID=${EDGEBIT_ID}" > /etc/edgebit/config.env
	echo "EDGEBIT_URL=${EDGEBIT_URL}" >> /etc/edgebit/config.env
	echo "RUST_LOG=info" >> /etc/edgebit/config.env
	echo "SYFT_CONFIG_FILE=${PREFIX}/edgebit/data/.syft.yaml" >> /etc/edgebit/config.env

	echo "Reloading systemd"
	systemctl daemon-reload

	echo "Enabling unit"
	systemctl enable edgebit-agent

	echo "Starting agent"
	systemctl start edgebit-agent
}

if [ $(whoami) != "root" ]; then
	die "Please run as root"
fi

if [ -z "$EDGEBIT_ID" ]; then
	die "\$EDGEBIT_ID must be set"
fi

if which systemctl >/dev/null; then
	echo "systemd detected"
	has_systemd="1"
else
	echo "No systemd detected"
	has_systemd=
fi

# Some checks to make sure that the system is usable for us
[ -r /sys/kernel/tracing ] || [ -r /sys/kernel/debug/tracing ] || die "tracefs is not available"
[ -r /sys/kernel/btf/vmlinux ] || die "BTF information is not available"

mkdir -p "$PREFIX"
cd "$PREFIX"

# Download agent and syft
echo "Downloading and extracting agent"
if [ -r "$TARBALL_URL" ]; then
	tar xzf "$TARBALL_URL"
else
	curl "$TARBALL_URL" | tar xz
fi

if [ "$has_systemd" = "1" ]; then
	systemd_install

	echo "EdgeBit agent was installed into $PREFIX/edgebit and edgebit-agent.service"
	echo "was enabled with systemd to start on boot"
else
	echo "EdgeBit agent was installed into $PREFIX/edgebit. To start it, run:"
	echo "$PREFIX/edgebit/bin/edgebit-agent"
fi
