#!/usr/bin/env bash
set -euo pipefail

# Run Grafana Tempo in Docker, expose HTTP API on 3200 and OTLP gRPC on 4317 (internal).
# This is a minimal setup storing data on local disk under /tmp/tempo.

TEMPO_DIR="${TEMPO_DIR:-/tmp/tempo}"
NET_NAME="netagent-demo"
TEMPO_IMAGE="${TEMPO_IMAGE:-grafana/tempo:latest}"
# Optional host bind for OTLP gRPC. If unset, OTLP listens only inside the docker network.
HOST_OTLP_PORT="${HOST_OTLP_PORT:-}"
TEMPO_UID="${TEMPO_UID:-10001}"
TEMPO_GID="${TEMPO_GID:-10001}"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not found. Install Docker to use this script." >&2
  exit 1
fi

if ! docker ps >/dev/null 2>&1; then
  echo "docker daemon not running or not accessible." >&2
  exit 1
fi

rm -rf "${TEMPO_DIR}"
mkdir -p "${TEMPO_DIR}"
# Ensure writable for non-root tempo user inside container
chmod 777 "${TEMPO_DIR}" || true
if [[ "${EUID}" -eq 0 ]]; then
  chown -R "${TEMPO_UID}:${TEMPO_GID}" "${TEMPO_DIR}" || true
fi

cat > "${TEMPO_DIR}/tempo.yaml" <<'EOF'
server:
  http_listen_port: 3200

distributor:
  receivers:
    otlp:
      protocols:
        grpc:
          endpoint: 0.0.0.0:4317

ingester:
  trace_idle_period: 10s
  max_block_duration: 5m

compactor:
  compaction:
    block_retention: 24h

storage:
  trace:
    backend: local
    local:
      path: /tmp/tempo/blocks
    wal:
      path: /tmp/tempo/wal
EOF

if ! docker network inspect "${NET_NAME}" >/dev/null 2>&1; then
  docker network create "${NET_NAME}" >/dev/null
fi

docker rm -f tempo >/dev/null 2>&1 || true
OTLP_PORT_MAPPING=()
if [[ -n "${HOST_OTLP_PORT}" ]]; then
  OTLP_PORT_MAPPING=(-p "${HOST_OTLP_PORT}:4317")
fi

docker run -d --name tempo --network "${NET_NAME}" \
  -p 3200:3200 "${OTLP_PORT_MAPPING[@]}" \
  -v "${TEMPO_DIR}/tempo.yaml:/etc/tempo.yaml:ro" \
  -v "${TEMPO_DIR}:/tmp/tempo" \
  "${TEMPO_IMAGE}" \
  -config.file=/etc/tempo.yaml

echo "Tempo running:
- HTTP API: http://localhost:3200
- OTLP gRPC receiver: 4317 (inside docker network as 'tempo')
Set your OTel exporter/collector to send to tempo:4317 inside the docker network."
if [[ -n "${HOST_OTLP_PORT}" ]]; then
  echo "Host OTLP gRPC mapped on :${HOST_OTLP_PORT}"
fi
echo "Data dir: ${TEMPO_DIR} (ensure write perms; chmod 777 if needed)"
