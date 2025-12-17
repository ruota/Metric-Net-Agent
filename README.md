# MNA (Metric Net Agent)

MNA is a lightweight eBPF-based daemon that counts outbound TCP connect
events per process and exports the data as Prometheus metrics. It attaches a
`kprobe` to `tcp_v4_connect`, filters events based on the configured process
list, and increments the `netagent_connect_total{process,proto,dport}` counter
that is scraped from `/metrics`. UDP `udp_sendmsg` events are also counted, and
send→recv durations are tracked via `netagent_tx_duration_seconds`. Optionally,
durations are sent as OpenTelemetry spans to an OTLP collector.

## Requirements

- Ubuntu 24.04 (or another kernel with BTF information and eBPF enabled)
- Root privileges to attach kprobes and read `/proc/<pid>/comm`
- Go 1.21+ to build the Go binaries and run `bpf2go`
- Clang/LLVM, libbpf, libelf, zlib, and Linux headers to build the eBPF object

For Ubuntu 24.x hosts you can install the prerequisites with:

```bash
sudo ./scripts/install-deps-ubuntu24.sh
```

The script installs the required apt packages and fetches the `bpf2go` helper
matching the version declared in `go.mod`.

The Ubuntu dependency script also installs `bpftool`; use it to generate the
`bpf/vmlinux.h` header (required by `bpf2go`) with:

```bash
./scripts/gen-vmlinux.sh
```

This uses the kernel BTF data from `/sys/kernel/btf/vmlinux`.

To automatically download the Go modules, generate the eBPF bindings, and install
the Go binaries used by this project, run (as your normal user, not root):

```bash
./scripts/install-go-packages.sh
```

This pulls the dependencies in `go.mod`, generates `bpf/vmlinux.h`, installs
`bpf2go`, runs `go generate` for `internal/ebpf`, and installs the `netagent`
binary into `$GOBIN` (defaults to `$GOPATH/bin`).

## Quick start

If you use `./scripts/install-go-packages.sh`, the Go dependencies and generated
bindings are handled for you and the `netagent` binary is installed into your Go
bin directory; you can skip `make gen`/`make build` unless you want a local
`./netagent` binary.

1. Install the dependencies (see above).
2. Generate `bpf/vmlinux.h` if missing:
   ```bash
   ./scripts/gen-vmlinux.sh
   ```
3. Generate the eBPF Go bindings:
   ```bash
   make gen
   ```
4. Adjust `config.yaml` to list the processes you want to monitor.
5. Build MNA:
   ```bash
   make build
   ```
6. Run the agent (must run as root to attach eBPF programs):
   ```bash
   sudo ./netagent -config config.yaml
   # or simply
   sudo make run
   ```
7. Scrape the Prometheus endpoint:
   ```bash
   curl http://localhost:9102/metrics
   ```

### End-to-end stack (Tempo + Collector + Prometheus + Grafana)

1. Start the stack (Docker required):
   ```bash
   ./scripts/run-observability-stack.sh
   ```
   This brings up:
   - Tempo on :3200 (OTLP gRPC on :4318 by default, override HOST_OTLP_PORT)
   - OTel Collector on :4317 (override COLLECTOR_OTLP_PORT) exporting to Tempo
   - Prometheus on :9090 scraping NETAGENT_ADDR (default host.docker.internal:9102)
   - Grafana on :3000 (admin/admin)
2. Configure MNA (`config.yaml`) with the processes you want to trace/measure and point OTLP to the collector:
   ```yaml
   interfaces: ["eth0"]
   targets:
     - name: "app"
       match_comm: "myapp"       # /proc/<pid>/comm of your app
     - name: "db"
       match_comm: "postgres"    # example DB process
   export:
     listen_addr: ":9102"
   otel:
     endpoint: "127.0.0.1:4317"  # collector from the stack
     insecure: true
   ```
3. Run MNA as root with that config:
   ```bash
   sudo ./netagent -config config.yaml
   ```
4. In Grafana, add datasources:
   - Prometheus: `http://prom:9090`
   - Tempo: `http://tempo:3200`
   Import `dashboards/netagent-grafana.json` for metrics; use Explore+Tempo for traces.

### Docker Compose alternative

If you prefer Docker Compose instead of the helper script:
```bash
cd deploy/observability
docker compose up -d
```
Services exposed:
- Grafana: http://localhost:3000 (admin/admin)
- Prometheus: http://localhost:9090
- Tempo: http://localhost:3200 (OTLP gRPC host :4318 → container 4317)
- OTel Collector: OTLP gRPC on :4317 (host)

Notes:
- Update `deploy/observability/prometheus.yml` if MNA is not on `host.docker.internal:9102`.
- Override images/ports via env (e.g., `COLLECTOR_OTLP_PORT=14317 docker compose up -d`).

## Configuration

`config.yaml` controls the allow list of processes and the HTTP server:

```yaml
interfaces: ["eth0"]    # reserved for future filtering
targets:
  - name: "nginx"       # label used in Prometheus metrics
    match_comm: "nginx" # value from /proc/<pid>/comm
export:
  listen_addr: ":9102"  # address where /metrics is served
otel:
  endpoint: ""          # set to OTLP collector address (host:port) to emit spans
  insecure: true        # set true for plaintext OTLP
```

Only processes whose `/proc/<pid>/comm` matches a `match_comm` entry produce
metrics. Each matching process increments the `netagent_connect_total`
counter with `process=<name>`, `proto=<tcp|udp>`, and `dport=<destination port>`.
Durations feed `netagent_tx_duration_seconds`; edges feed `netagent_edge_total`.

If you set `otel.endpoint`, send→recv durations are also emitted as OTel spans
named `<process> -> <dst_ip>:<dport> (<proto>)` with attributes for process,
proto, dport, dst_ip, src_ip (when available), sport, and socket pointer. The
trace ID is derived deterministically from the 4-tuple (src_ip, sport, dst_ip,
dport, proto) so the same flow observed on multiple hosts ends up in the same
trace when MNA runs on both sides.

### TraceQL examples (Tempo)

- MNA traces with flow_id (client+server in the same trace):
  ```traceql
  {resource.service.name="mna", .flow_id != nil}
  ```
- Filter by process and DB:
  ```traceql
  {resource.service.name="mna", .process="app", .dport="5432"}
  ```
- Filter by destination:
  ```traceql
  {resource.service.name="mna", .dst_ip="10.0.0.5", .dport="443"}
  ```

## Metrics

- `netagent_connect_total{process,proto,dport}`: TCP/UDP connect/send events.
- `netagent_edge_total{process,proto,dport,dst_ip}`: observed edges by destination IP/port.
- `netagent_connect_total{process,proto,dport,dst_ip}`: TCP/UDP connect/send events by destination IP/port (higher cardinality).
- `netagent_tx_duration_seconds{process,proto,dport,dst_ip}` (histogram): send→recv durations per destination IP/port (higher cardinality).

### Useful PromQL snippets

- P95 latency to Postgres 5432 from app:
  ```promql
  histogram_quantile(0.95,
    sum by (le,process,proto,dport,dst_ip) (
      rate(netagent_tx_duration_seconds_bucket{process="app",proto="tcp",dport="5432"}[5m])
    )
  )
  ```
- Node map (process → destination IP/port):
  ```promql
  sum by (process,proto,dport,dst_ip) (increase(netagent_edge_total[5m]))
  ```
- Connection rate to a specific DB:
  ```promql
  sum by (process,proto,dport,dst_ip) (
    rate(netagent_connect_total{proto="tcp",dport="5432"}[5m])
  )
  ```

## Development notes

- `make gen` runs `bpf2go` (from `github.com/cilium/ebpf`) to compile
  `bpf/net.bpf.c` into Go bindings under `internal/ebpf`.
- `make build` compiles the Go command in `cmd/netagent`.
- `make run` builds and launches MNA with `sudo`.

The agent currently listens only to IPv4 TCP connect events via the
`tcp_v4_connect` kprobe. IPv6 support and per-interface filtering can be added
by extending `bpf/net.bpf.c` and the loader.

## Smoke test script

You can run an automated smoke test (requires root for kprobe attach):

```bash
sudo ./scripts/smoke-test.sh
```

The script starts MNA with a temporary config targeting `curl`, generates
a couple of outbound connections with `curl`, and prints the observed
`netagent_connect_total` metrics. Override `NETAGENT_BIN` to point to a
different binary and `METRICS_PORT` to change the listen port.
If you see memlock errors, raise the limit first (e.g., `ulimit -l unlimited`
or `sudo prlimit --pid $$ --memlock=unlimited`).
The smoke test requires the ability to load eBPF programs (cap_bpf or
cap_sys_admin); in restricted containers without these caps it will exit early.

## Grafana dashboard

A ready-to-import Grafana dashboard is available at `dashboards/netagent-grafana.json`.
Configure Prometheus to scrape `http://<mna-host>:9102/metrics`, add the
Prometheus datasource in Grafana, then import the JSON to visualize TCP connect
rates by process and destination port.

For a quick local Grafana + Prometheus demo (Docker required), run:

```bash
NETAGENT_ADDR=localhost:9102 ./scripts/run-grafana-demo.sh
```

Then open http://localhost:3000 (admin/admin), add a Prometheus datasource with
URL `http://prom:9090`, and import `dashboards/netagent-grafana.json`.

Note: on Linux the script adds `host.docker.internal` → host gateway for the
Prometheus container; set `NETAGENT_ADDR` accordingly if MNA is elsewhere.

If you prefer to run Prometheus locally without Docker/systemd, use:

```bash
NETAGENT_ADDR=localhost:9102 ./scripts/run-prometheus-local.sh
```

It downloads Prometheus into `.prometheus/`, scrapes MNA on `NETAGENT_ADDR`
and listens on `:9090`. Point Grafana to `http://localhost:9090` in that case.

If you want Prometheus in Docker with the config generated for you:

```bash
NETAGENT_ADDR=host.docker.internal:9102 ./scripts/run-prometheus-docker.sh
```

This writes `/tmp/prom-netagent/prometheus.yml`, ensures the `netagent-demo`
network exists, and runs a `prom` container on port 9090.

To run an OpenTelemetry Collector in Docker with OTLP gRPC on 4317 and Prometheus
export on 9464:

```bash
./scripts/run-otel-collector.sh
```

Then set in `config.yaml`:

```yaml
otel:
  endpoint: "otelcol:4317"
  insecure: true
```

Override the image with `COLLECTOR_IMAGE` if needed (default: otel/opentelemetry-collector-contrib:0.102.0).

If you need a Tempo backend for traces, start it with:

```bash
./scripts/run-tempo-docker.sh
```

Tempo listens on 3200 (HTTP API) and 4317 (OTLP gRPC). Point your collector
OTLP exporter to `tempo:4317` inside the docker network. If 4317 is busy on the
host, set `HOST_OTLP_PORT=14317 ./scripts/run-tempo-docker.sh` to map a different
host port (inside the network it remains 4317). Ensure `TEMPO_DIR` is writable (the
script sets chmod 777 by default; override TEMPO_DIR/TEMPO_UID/TEMPO_GID as needed).

To visualize nodes/edges in Grafana, add a “Node graph” panel with the query:

```
sum by (process, proto, dport, dst_ip) (increase(netagent_edge_total[$__interval]))
```

Map `process` → source, `dst_ip` → target, and show `dport`/`proto` in the label.
The “P95 duration” panel uses `netagent_tx_duration_seconds`; set the unit to
milliseconds if you prefer.

## OpenTelemetry export

Set `otel.endpoint` in `config.yaml` (e.g., `collector:4317`) to emit spans for send→recv durations.
If your collector expects plaintext, set `otel.insecure: true`. Span names follow
`<process> -> <dst_ip>:<port> (<proto>)` with attributes for process, proto,
dst_ip, dport, src_ip (when available), and socket pointer.

### OTel C++ client example

Under `clients/otel_cpp_client` there is a minimal OTLP client using
`opentelemetry-cpp`. Build with CMake after installing opentelemetry-cpp (with
OTLP gRPC exporter):

```bash
cd clients/otel_cpp_client
cmake -S . -B build
cmake --build build
```

Run and send a test span (configure via env vars):

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=collector:4317 \
NETAGENT_PROCESS=myapp \
NETAGENT_PROTO=tcp \
NETAGENT_DST_IP=10.0.0.5 \
NETAGENT_DST_PORT=5432 \
NETAGENT_DURATION_MS=120 \
./build/otel_cpp_client
```

This emits a span named `<process> -> <dst_ip>:<port> (<proto>)` to the OTLP
collector with the attributes matching the MNA format.

## License

MNA (Metric Net Agent) is released under the GNU GPLv3. Copyright (C) Alessio Lama.
