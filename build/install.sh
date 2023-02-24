#!/bin/sh -e

arch=$(uname -i)

: "${VERSION:=0.0.9}"
: "${TARBALL_URL:=https://install.edgebit.io/edgebit-${arch}-v${VERSION}.tar.gz}"
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
syft_config: "${PREFIX}/edgebit/data/syft.yaml"
EOF
	fi
}

systemd_install() {
	echo "Installing files"
	install "${PREFIX}/edgebit/data/edgebit-agent.service" /usr/lib/systemd/system/

	echo "Reloading systemd"
	systemctl daemon-reload

	echo "Enabling unit"
	systemctl enable edgebit-agent

	echo "Starting agent"
	systemctl restart edgebit-agent
}

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
if [ -r "$TARBALL_URL" ]; then
	tar xzf "$TARBALL_URL"
else
	curl "$TARBALL_URL" | tar xz
fi

mkdir -p /etc/edgebit
make_config

if [ "$has_systemd" = "1" ]; then
	systemd_install

	echo "EdgeBit agent was installed into $PREFIX/edgebit and edgebit-agent.service"
	echo "was enabled with systemd to start on boot"
else
	echo "EdgeBit agent was installed into $PREFIX/edgebit. To start it, run:"
	echo "$PREFIX/edgebit/bin/edgebit-agent"
fi
