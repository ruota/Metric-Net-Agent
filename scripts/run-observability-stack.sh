#!/usr/bin/env bash
set -euo pipefail

# Start a complete observability stack (Tempo + OTel Collector + Prometheus + Grafana)
# using Docker. MNA runs on the host and sends OTLP traces to the collector;
# Prometheus scrapes MNA metrics.
#
# Ports (override via env):
# - Tempo HTTP/UI:        3200
# - Tempo OTLP gRPC:      HOST_OTLP_PORT (default 4318) mapped to container 4317
# - Collector OTLP gRPC:  COLLECTOR_OTLP_PORT (default 4317)
# - Prometheus:           9090
# - Grafana:              3000

NET_NAME="netagent-demo"
TEMPO_DIR="${TEMPO_DIR:-/tmp/tempo-stack}"
COLLECTOR_DIR="${COLLECTOR_DIR:-/tmp/netagent-collector}"
PROM_DIR="${PROM_DIR:-/tmp/prom-netagent}"
HOST_OTLP_PORT="${HOST_OTLP_PORT:-4318}"           # host-facing Tempo OTLP gRPC
COLLECTOR_OTLP_PORT="${COLLECTOR_OTLP_PORT:-4317}" # collector OTLP gRPC
NETAGENT_ADDR="${NETAGENT_ADDR:-host.docker.internal:9102}"
TEMPO_IMAGE="${TEMPO_IMAGE:-grafana/tempo:latest}"
COLLECTOR_IMAGE="${COLLECTOR_IMAGE:-otel/opentelemetry-collector-contrib:0.102.0}"
PROM_IMAGE="${PROM_IMAGE:-prom/prometheus}"
GRAFANA_IMAGE="${GRAFANA_IMAGE:-grafana/grafana}"

need() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "missing dependency: $1" >&2
		exit 1
	fi
}

need docker
if ! docker ps >/dev/null 2>&1; then
	echo "docker daemon not running or not accessible." >&2
	exit 1
fi

if ! docker network inspect "${NET_NAME}" >/dev/null 2>&1; then
	echo "Creating docker network ${NET_NAME}..."
	docker network create "${NET_NAME}" >/dev/null
fi

echo "=== Tempo ==="
rm -rf "${TEMPO_DIR}"
mkdir -p "${TEMPO_DIR}"
chmod 777 "${TEMPO_DIR}" || true
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

metrics_generator:
  registry:
    collection_interval: 10s
  processor:
    span_metrics:
      dimensions: ["service.name", "name", "status.code"]
    service_graphs:
      dimensions: ["service.name"]
  storage:
    path: /tmp/tempo/generator
  ring:
    kvstore:
      store: inmemory
EOF

docker rm -f tempo >/dev/null 2>&1 || true
docker run -d --name tempo --network "${NET_NAME}" \
  -p 3200:3200 -p "${HOST_OTLP_PORT}:4317" \
  -v "${TEMPO_DIR}/tempo.yaml:/etc/tempo.yaml:ro" \
  -v "${TEMPO_DIR}:/tmp/tempo" \
  "${TEMPO_IMAGE}" \
  -config.file=/etc/tempo.yaml >/dev/null

echo "Tempo up: UI http://localhost:3200, OTLP gRPC on host :${HOST_OTLP_PORT}"

echo "=== OTel Collector ==="
rm -rf "${COLLECTOR_DIR}"
mkdir -p "${COLLECTOR_DIR}"
cat > "${COLLECTOR_DIR}/collector.yaml" <<EOF
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317

processors:
  batch: {}

exporters:
  debug:
    verbosity: normal
  otlp/tempo:
    endpoint: "tempo:4317"
    tls:
      insecure: true

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [otlp/tempo, debug]
EOF

docker rm -f otelcol >/dev/null 2>&1 || true
docker run -d --name otelcol --network "${NET_NAME}" \
  -p "${COLLECTOR_OTLP_PORT}:4317" \
  -v "${COLLECTOR_DIR}/collector.yaml:/etc/otelcol/collector.yaml:ro" \
  "${COLLECTOR_IMAGE}" \
  --config /etc/otelcol/collector.yaml >/dev/null

echo "Collector up: OTLP gRPC on host :${COLLECTOR_OTLP_PORT}, exporting to tempo:4317 (debug exporter enabled)."

echo "=== Prometheus ==="
mkdir -p "${PROM_DIR}"
cat > "${PROM_DIR}/prometheus.yml" <<EOF
global:
  scrape_interval: 5s
scrape_configs:
  - job_name: netagent
    static_configs:
      - targets: ['${NETAGENT_ADDR}']
EOF
docker rm -f prom >/dev/null 2>&1 || true
docker run -d --name prom --network "${NET_NAME}" \
  --add-host=host.docker.internal:host-gateway \
  -p 9090:9090 \
  -v "${PROM_DIR}/prometheus.yml:/etc/prometheus/prometheus.yml:ro" \
  "${PROM_IMAGE}" >/dev/null
echo "Prometheus up: http://localhost:9090 scraping ${NETAGENT_ADDR}"

echo "=== Grafana ==="
docker rm -f grafana >/dev/null 2>&1 || true
docker run -d --name grafana --network "${NET_NAME}" -p 3000:3000 "${GRAFANA_IMAGE}" >/dev/null
echo "Grafana up: http://localhost:3000 (admin/admin)."
echo "Add datasources:"
echo "  - Prometheus: http://prom:9090"
echo "  - Tempo:      http://tempo:3200"
echo
echo "MNA config hints:"
echo "  otel.endpoint: \"127.0.0.1:${COLLECTOR_OTLP_PORT}\""
echo "  otel.insecure: true"
echo "Targets: set match_comm for the processes you want traced/metricated."
