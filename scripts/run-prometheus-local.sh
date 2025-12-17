#!/usr/bin/env bash
set -euo pipefail

# Download and run Prometheus locally (no Docker/systemd) with a minimal config
# that scrapes NetAgent at NETAGENT_ADDR (default: localhost:9102).

PROM_VERSION="${PROM_VERSION:-2.53.1}"
NETAGENT_ADDR="${NETAGENT_ADDR:-localhost:9102}"
PROM_LISTEN_ADDR="${PROM_LISTEN_ADDR:-0.0.0.0:9090}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROM_DIR="${PROM_DIR:-${ROOT}/.prometheus}"
PROM_BIN="${PROM_DIR}/prometheus"
PROM_TARBALL="prometheus-${PROM_VERSION}.linux-amd64.tar.gz"
PROM_URL="https://github.com/prometheus/prometheus/releases/download/v${PROM_VERSION}/${PROM_TARBALL}"

mkdir -p "${PROM_DIR}"

if [[ ! -x "${PROM_BIN}" ]]; then
	echo "Downloading Prometheus ${PROM_VERSION}..."
	TMP="$(mktemp -d)"
	curl -L "${PROM_URL}" -o "${TMP}/${PROM_TARBALL}"
	tar -xzf "${TMP}/${PROM_TARBALL}" -C "${TMP}"
	mv "${TMP}/prometheus-${PROM_VERSION}.linux-amd64/prometheus" "${PROM_BIN}"
	mv "${TMP}/prometheus-${PROM_VERSION}.linux-amd64/promtool" "${PROM_DIR}/promtool"
	rm -rf "${TMP}"
fi

cat >"${PROM_DIR}/prom.yml" <<EOF
global:
  scrape_interval: 5s
scrape_configs:
  - job_name: netagent
    static_configs:
      - targets: ['${NETAGENT_ADDR}']
EOF

mkdir -p "${PROM_DIR}/data"

echo "Starting Prometheus on :9090 scraping ${NETAGENT_ADDR}..."
exec "${PROM_BIN}" \
  --config.file="${PROM_DIR}/prom.yml" \
  --storage.tsdb.path="${PROM_DIR}/data" \
  --web.listen-address="${PROM_LISTEN_ADDR}"
