#!/usr/bin/env bash
set -euo pipefail

# This script starts a local Prometheus (scraping NetAgent) and Grafana using Docker.
# It assumes NetAgent metrics are reachable at NETAGENT_ADDR (host:port).
# After it starts, open Grafana at http://localhost:3000 (admin/admin by default),
# add the Prometheus datasource pointing to http://prom:9090, and import
# dashboards/netagent-grafana.json.

NETAGENT_ADDR="${NETAGENT_ADDR:-host.docker.internal:9102}"
PROM_DIR="${PROM_DIR:-/tmp/prom-netagent}"
PROM_CONFIG="${PROM_DIR}/prometheus.yml"
NET_NAME="netagent-demo"

if ! command -v docker >/dev/null 2>&1; then
	echo "docker not found. Install Docker to use this demo." >&2
	exit 1
fi

if ! docker ps >/dev/null 2>&1; then
	echo "docker daemon not running or not accessible." >&2
	exit 1
fi

mkdir -p "${PROM_DIR}"
cat > "${PROM_CONFIG}" <<EOF
global:
  scrape_interval: 5s
scrape_configs:
  - job_name: netagent
    static_configs:
      - targets: ['${NETAGENT_ADDR}']
EOF
chmod 644 "${PROM_CONFIG}"

if ! docker network inspect "${NET_NAME}" >/dev/null 2>&1; then
	echo "Creating Docker network ${NET_NAME}..."
	docker network create "${NET_NAME}" >/dev/null
fi

echo "Starting Prometheus (scraping ${NETAGENT_ADDR})..."
docker rm -f prom >/dev/null 2>&1 || true
docker run -d --name prom --network "${NET_NAME}" \
  --add-host=host.docker.internal:host-gateway \
  -p 9090:9090 \
  -v "${PROM_CONFIG}:/etc/prometheus/prometheus.yml:ro" \
  prom/prometheus >/dev/null

echo "Starting Grafana..."
docker rm -f grafana >/dev/null 2>&1 || true
docker run -d --name grafana --network "${NET_NAME}" -p 3000:3000 grafana/grafana >/dev/null

echo "Grafana is up at http://localhost:3000 (admin/admin)."
echo "1) Add Prometheus datasource with URL: http://prom:9090"
echo "2) Import dashboards/netagent-grafana.json"
