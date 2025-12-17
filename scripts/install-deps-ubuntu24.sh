#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
	echo "This script must be run as root (try: sudo $0)" >&2
	exit 1
fi

if [[ -r /etc/os-release ]]; then
	. /etc/os-release
	if [[ "${ID}" != "ubuntu" || "${VERSION_ID%%.*}" != "24" ]]; then
		echo "Warning: this script targets Ubuntu 24.x (detected ${PRETTY_NAME:-unknown})." >&2
	fi
else
	echo "Warning: unable to read /etc/os-release to verify the distro." >&2
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y \
	build-essential \
	clang \
	llvm \
	libbpf-dev \
	libelf-dev \
	zlib1g-dev \
	pkg-config \
	make \
	golang-go \
	"linux-headers-$(uname -r)" \
	linux-tools-common \
	"linux-tools-$(uname -r)"

# Ensure bpftool is on PATH (linux-tools installs it under /usr/lib/linux-tools-<kernel>/bpftool)
BPFTOOL_BIN="/usr/lib/linux-tools-$(uname -r)/bpftool"
if [[ -x "${BPFTOOL_BIN}" ]]; then
	ln -sf "${BPFTOOL_BIN}" /usr/local/bin/bpftool
fi

if ! command -v go >/dev/null 2>&1; then
	echo "Go binary not found after installation; ensure golang-go is in PATH before continuing." >&2
	exit 1
fi

echo "Installing bpf2go helper (required by go generate)..."
BPF2GO_PKG="github.com/cilium/ebpf/cmd/bpf2go@v0.16.0"
INSTALL_USER="${SUDO_USER:-root}"
GO_INSTALL_CMD="GO111MODULE=on go install ${BPF2GO_PKG}"

if [[ "${INSTALL_USER}" != "root" ]]; then
	su - "${INSTALL_USER}" -c "${GO_INSTALL_CMD}"
else
	eval "${GO_INSTALL_CMD}"
fi

echo "Dependencies installed. Ensure \$HOME/go/bin is on your PATH to use bpf2go."
