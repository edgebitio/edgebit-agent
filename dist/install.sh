#!/bin/sh -e

arch=$(uname -m)

: "${VERSION:=0.4.1}"
: "${TARBALL_URL:=https://github.com/edgebitio/edgebit-agent/releases/download/v${VERSION}/edgebit-agent-${VERSION}.${arch}.tar.gz}"
: "${PREFIX:=/opt}"
: "${EDGEBIT_CONFIG:=/etc/edgebit/config.yaml}"

die() {
	echo "Error: $1" >> /dev/stderr
	exit 1
}

make_config() {
	# only write out the config if it's not present
	if [ ! -e "$EDGEBIT_CONFIG" ]; then
		echo "Writing out $EDGEBIT_CONFIG"
		cat > "$EDGEBIT_CONFIG"  <<EOF
edgebit_id: "${EDGEBIT_ID}"
edgebit_url: "${EDGEBIT_URL}"
syft_config: "${PREFIX}/edgebit/syft.yaml"
syft_path: "${PREFIX}/edgebit/syft/syft"
EOF
	fi
}

systemd_install() {
	echo "Installing files"

	unit_src="${PREFIX}/edgebit/edgebit-agent.service"
	unit_dst=/usr/lib/systemd/system/
	unit_dst2=/etc/systemd/system/

	if ! install "$unit_src" "$unit_dst" 2>/dev/null; then
		echo "Could not install Systemd unit to $unit_dst, trying $unit_dst2"
		# if it failed to install, it's probably because /usr is read-only.
		# fall back to /etc
		install "$unit_src" "$unit_dst2"
	fi

	echo "Reloading systemd"
	systemctl daemon-reload

	echo "Enabling unit"
	systemctl enable edgebit-agent

	echo "Starting agent"
	systemctl restart edgebit-agent
}

if [ "$arch" != "x86_64" ] && [ "$arch" != "aarch64" ]; then
	die "Only x86_64 and aarch64 are supported at this time"
fi

if [ $(whoami) != "root" ]; then
	die "Please run as root"
fi

if [ -z "$EDGEBIT_ID" ]; then
	die "\$EDGEBIT_ID must be set"
fi

if [ -z "$EDGEBIT_URL" ]; then
	die "\$EDGEBIT_URL must be set"
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
if [ -f "$TARBALL_URL" ]; then
	tar xzf "$TARBALL_URL"
else
	curl -sL "$TARBALL_URL" | tar xz
fi

mkdir -p /etc/edgebit
make_config

if [ "$has_systemd" = "1" ]; then
	systemd_install

	echo "EdgeBit agent was installed into $PREFIX/edgebit and edgebit-agent.service"
	echo "was enabled with systemd to start on boot"
else
	echo "EdgeBit agent was installed into $PREFIX/edgebit. To start it, run:"
	echo "$PREFIX/edgebit/edgebit-agent"
fi
