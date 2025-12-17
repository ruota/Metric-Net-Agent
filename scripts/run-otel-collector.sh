#!/usr/bin/env bash
set -euo pipefail

# Run an OpenTelemetry Collector in Docker with a minimal pipeline:
# - OTLP gRPC receiver on 4317
# - Prometheus exporter on 9464 (optional metrics scrape)
# - Debug exporter for quick inspection
# - OTLP exporter to Tempo (for traces) and optional upstream passthrough

COLLECTOR_DIR="${COLLECTOR_DIR:-/tmp/netagent-collector}"
COLLECTOR_IMAGE="${COLLECTOR_IMAGE:-otel/opentelemetry-collector-contrib:0.102.0}"
NET_NAME="netagent-demo"
# Tempo/OTLP endpoint for traces. Override if Tempo is exposed on host (e.g., HOST_OTLP_PORT=4318).
TEMPO_ENDPOINT="${TEMPO_ENDPOINT:-tempo:4317}"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not found. Install Docker to use this script." >&2
  exit 1
fi

if ! docker ps >/dev/null 2>&1; then
  echo "docker daemon not running or not accessible." >&2
  exit 1
fi

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
    verbosity: basic
  prometheus:
    endpoint: "0.0.0.0:9464"
    namespace: "otelcol"
  otlp/tempo:
    endpoint: "${TEMPO_ENDPOINT}"
    tls:
      insecure: true
#  otlp/upstream:
#    endpoint: "<upstream-collector>:4317"
#    tls:
#      insecure: true

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [otlp/tempo, debug]
    metrics:
      receivers: [otlp]
      processors: [batch]
      exporters: [prometheus]
EOF

if ! docker network inspect "${NET_NAME}" >/dev/null 2>&1; then
  docker network create "${NET_NAME}" >/dev/null
fi

docker rm -f otelcol >/dev/null 2>&1 || true
docker run -d --name otelcol --network "${NET_NAME}" \
  -p 4317:4317 -p 9464:9464 \
  -v "${COLLECTOR_DIR}/collector.yaml:/etc/otelcol/collector.yaml:ro" \
  "${COLLECTOR_IMAGE}" \
  --config /etc/otelcol/collector.yaml

echo "OTel Collector running:
- OTLP gRPC:      4317
- Prometheus expo:9464
- Debug exporter enabled (logs in container logs)"
echo "Set in config.yaml -> otel.endpoint: \"otelcol:4317\" and otel.insecure: true for MNA."
