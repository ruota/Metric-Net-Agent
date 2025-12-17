#!/usr/bin/env bash
set -euo pipefail

# Run Prometheus in Docker with a generated config that scrapes NETAGENT_ADDR.
# Defaults to host.docker.internal:9102 for Linux host access.

NETAGENT_ADDR="${NETAGENT_ADDR:-host.docker.internal:9102}"
PROM_DIR="${PROM_DIR:-/tmp/prom-netagent}"
NET_NAME="netagent-demo"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not found. Install Docker to use this script." >&2
  exit 1
fi

if ! docker ps >/dev/null 2>&1; then
  echo "docker daemon not running or not accessible." >&2
  exit 1
fi

rm -rf "${PROM_DIR}"
mkdir -p "${PROM_DIR}"

cat > "${PROM_DIR}/prometheus.yml" <<EOF
global:
  scrape_interval: 5s
scrape_configs:
  - job_name: netagent
    static_configs:
      - targets: ['${NETAGENT_ADDR}']
EOF
chmod 644 "${PROM_DIR}/prometheus.yml"

if ! docker network inspect "${NET_NAME}" >/dev/null 2>&1; then
  docker network create "${NET_NAME}" >/dev/null
fi

docker rm -f prom >/dev/null 2>&1 || true
docker run -d --name prom --network "${NET_NAME}" \
  --add-host=host.docker.internal:host-gateway \
  -p 9090:9090 \
  -v "${PROM_DIR}/prometheus.yml:/etc/prometheus/prometheus.yml:ro" \
  prom/prometheus

echo "Prometheus running on http://localhost:9090 (scraping ${NETAGENT_ADDR})"
