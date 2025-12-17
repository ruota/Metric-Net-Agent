#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [[ "${EUID}" -eq 0 ]]; then
	echo "Run this script without sudo so Go tools are installed to your user directory." >&2
	exit 1
fi

if ! command -v go >/dev/null 2>&1; then
	echo "Go toolchain not found. Install Go 1.21+ and ensure it is on your PATH." >&2
	exit 1
fi

cd "${REPO_ROOT}"

BPF2GO_PKG="github.com/cilium/ebpf/cmd/bpf2go@v0.16.0"

echo "Downloading Go module dependencies..."
go mod download

echo "Generating vmlinux.h (requires bpftool and kernel BTF)..."
"${SCRIPT_DIR}/gen-vmlinux.sh"

echo "Installing Go helper tools..."
go install "${BPF2GO_PKG}"

echo "Generating eBPF Go bindings..."
go generate ./internal/ebpf

echo "Installing NetAgent binary to your Go bin directory..."
go install ./cmd/netagent

GOBIN_PATH="$(go env GOBIN)"
if [[ -z "${GOBIN_PATH}" ]]; then
	GOBIN_PATH="$(go env GOPATH)/bin"
fi

echo "Go packages installed. Ensure ${GOBIN_PATH} is on your PATH."
