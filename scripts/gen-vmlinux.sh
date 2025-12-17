#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VMLINUX_BTF_FILE="${VMLINUX_BTF_FILE:-/sys/kernel/btf/vmlinux}"
VMLINUX_OUT="${REPO_ROOT}/bpf/vmlinux.h"

ALT_BPFTOOL_DIR="/usr/lib/linux-tools-$(uname -r)"
if [[ ":$PATH:" != *":${ALT_BPFTOOL_DIR}:"* && -x "${ALT_BPFTOOL_DIR}/bpftool" ]]; then
	PATH="${ALT_BPFTOOL_DIR}:${PATH}"
fi

if ! command -v bpftool >/dev/null 2>&1; then
	echo "bpftool is required to generate vmlinux.h (install via: sudo apt-get install -y bpftool)" >&2
	exit 1
fi

if [[ ! -r "${VMLINUX_BTF_FILE}" ]]; then
	echo "BTF file not found at ${VMLINUX_BTF_FILE}; ensure your kernel exposes BTF (linux-headers installed?)" >&2
	exit 1
fi

TMP="$(mktemp)"
echo "Generating ${VMLINUX_OUT} from ${VMLINUX_BTF_FILE}..."
bpftool btf dump file "${VMLINUX_BTF_FILE}" format c > "${TMP}"
mv "${TMP}" "${VMLINUX_OUT}"
echo "Done."
