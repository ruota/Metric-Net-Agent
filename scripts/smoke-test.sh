#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
	echo "Run this script as root (e.g., sudo ./scripts/smoke-test.sh) so eBPF can attach kprobes." >&2
	exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
	echo "curl is required to generate test traffic." >&2
	exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
	echo "python3 is required to run a local HTTP server for the test." >&2
	exit 1
fi

CAP_OK=1
if command -v capsh >/dev/null 2>&1; then
	CAP_OUTPUT="$(capsh --print)"
	CAP_BOUNDING="$(echo "${CAP_OUTPUT}" | grep -E '^Bounding set')"
	if ! echo "${CAP_BOUNDING}" | grep -Eq 'cap_bpf|cap_sys_admin'; then
		CAP_OK=0
	fi
fi
if [[ "${CAP_OK}" -ne 1 ]]; then
	echo "Missing cap_bpf/cap_sys_admin; cannot load eBPF in this environment. Run on a host/VM with those caps or a privileged container." >&2
	exit 1
fi

MEMLOCK_LIMIT="$(ulimit -l)"
if [[ "${MEMLOCK_LIMIT}" != "unlimited" ]]; then
	MEMLOCK_VAL="${MEMLOCK_LIMIT}"
	if [[ "${MEMLOCK_VAL}" -lt 8192 ]]; then
		echo "Current memlock limit is ${MEMLOCK_VAL} KB; attempting to raise via prlimit..." >&2
		if command -v prlimit >/dev/null 2>&1; then
			prlimit --pid $$ --memlock=unlimited >/dev/null 2>&1 || true
			MEMLOCK_LIMIT="$(ulimit -l)"
		fi
		if [[ "${MEMLOCK_LIMIT}" != "unlimited" ]] && [[ "${MEMLOCK_LIMIT}" -lt 8192 ]]; then
			echo "Memlock limit (${MEMLOCK_LIMIT} KB) is too low for eBPF maps. Set 'ulimit -l unlimited' (or a higher value) and rerun." >&2
			exit 1
		fi
	fi
fi

NETAGENT_BIN="${NETAGENT_BIN:-./netagent}"
METRICS_HOST="${METRICS_HOST:-localhost}"
METRICS_PORT="${METRICS_PORT:-9102}"
HTTP_PORT="${HTTP_PORT:-18080}"
PRESERVE_LOGS=0

if [[ ! -x "${NETAGENT_BIN}" ]]; then
	echo "NetAgent binary not found at ${NETAGENT_BIN}. Build with 'make build' or run install-go-packages first." >&2
	exit 1
fi

TMP_CONFIG="$(mktemp)"
TMP_LOG="$(mktemp)"
TMP_HTTP_LOG="$(mktemp)"

cat >"${TMP_CONFIG}" <<EOF
interfaces: ["eth0"]
targets:
  - name: "curl"
    match_comm: "curl"
export:
  listen_addr: ":${METRICS_PORT}"
EOF

cleanup() {
	if [[ -n "${AGENT_PID:-}" ]]; then
		kill "${AGENT_PID}" 2>/dev/null || true
	fi
	if [[ -n "${HTTP_PID:-}" ]]; then
		kill "${HTTP_PID}" 2>/dev/null || true
	fi
	rm -f "${TMP_CONFIG}"
	if [[ "${PRESERVE_LOGS}" -eq 0 ]]; then
		rm -f "${TMP_LOG}" "${TMP_HTTP_LOG}"
	else
		echo "Logs preserved:"
		echo "  NetAgent log: ${TMP_LOG}"
		echo "  HTTP server log: ${TMP_HTTP_LOG}"
	fi
}
trap cleanup EXIT

echo "Starting local IPv4 HTTP server on 127.0.0.1:${HTTP_PORT}..."
python3 -m http.server "${HTTP_PORT}" --bind 127.0.0.1 >"${TMP_HTTP_LOG}" 2>&1 &
HTTP_PID=$!

sleep 1

echo "Starting NetAgent with temporary config (listening on :${METRICS_PORT})..."
"${NETAGENT_BIN}" -config "${TMP_CONFIG}" >"${TMP_LOG}" 2>&1 &
AGENT_PID=$!

sleep 2

if ! kill -0 "${AGENT_PID}" 2>/dev/null; then
	PRESERVE_LOGS=1
	echo "NetAgent exited early. See log: ${TMP_LOG}"
	exit 1
fi

echo "Generating test TCP connects via curl to 127.0.0.1:${HTTP_PORT}..."
for i in {1..3}; do
	curl -4 -m 3 -s "http://127.0.0.1:${HTTP_PORT}" >/dev/null || true
done

sleep 1

METRICS="$(curl -s "http://${METRICS_HOST}:${METRICS_PORT}/metrics" | grep netagent_connect_total || true)"
echo "Metrics:"
echo "${METRICS}"

if echo "${METRICS}" | grep -q 'process="curl"'; then
	echo "SUCCESS: netagent_connect_total incremented for curl."
	PRESERVE_LOGS=0
else
	PRESERVE_LOGS=1
	echo "FAIL: no counters observed. See log: ${TMP_LOG}"
	exit 1
fi
