package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"example.com/netagent/internal/config"
	"example.com/netagent/internal/ebpf"
	"example.com/netagent/internal/metrics"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"
)

type event struct {
	Sk         uint64
	Pid        uint32
	Saddr      uint32
	Daddr      uint32
	Sport      uint16
	Dport      uint16
	Family     uint8
	Proto      uint8
	Op         uint8
	_          uint8
	DurationNs uint64
}

const (
	opConnect    = 1
	opTxDuration = 2
	commCacheTTL = 5 * time.Second
)

// pidComm reads /proc/<pid>/comm to get the short process name.
func pidComm(pid uint32) (string, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "", err
	}
	if len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1]
	}
	return string(b), nil
}

func ip4(u uint32) string {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, u) // skc_* addresses are host order in this path
	return net.IP(b).String()
}

func protoStr(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return "unknown"
	}
}

func canonicalFlowEndpoints(srcIP string, sport uint16, dstIP string, dport uint16) (string, string) {
	a := fmt.Sprintf("%s:%d", srcIP, sport)
	b := fmt.Sprintf("%s:%d", dstIP, dport)
	if a > b {
		return b, a
	}
	return a, b
}

// flowTraceContext builds a deterministic TraceID for a 4-tuple so spans on client/server
// (both running NetAgent) land in the same trace. Returns context, flowID string, ok.
func flowTraceContext(srcIP string, sport uint16, dstIP string, dport uint16, proto string) (trace.SpanContext, string, bool) {
	if srcIP == "" || dstIP == "" || sport == 0 || dport == 0 {
		return trace.SpanContext{}, "", false
	}
	e1, e2 := canonicalFlowEndpoints(srcIP, sport, dstIP, dport)
	key := proto + "|" + e1 + "|" + e2
	sum := sha256.Sum256([]byte(key))
	var tid trace.TraceID
	copy(tid[:], sum[:16])
	parent := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    tid,
		TraceFlags: trace.FlagsSampled,
		Remote:     true,
	})
	return parent, hex.EncodeToString(sum[:16]), true
}

func setupTracer(ctx context.Context, cfg config.Otel) (*sdktrace.TracerProvider, error) {
	if cfg.Endpoint == "" {
		log.Printf("otel tracing disabled: no endpoint configured")
		return nil, nil
	}
	opts := []otlptracegrpc.Option{otlptracegrpc.WithEndpoint(cfg.Endpoint)}
	if cfg.Insecure {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}
	exp, err := otlptrace.New(ctx, otlptracegrpc.NewClient(opts...))
	if err != nil {
		return nil, fmt.Errorf("otlp exporter: %w", err)
	}
	log.Printf("otel tracing enabled: endpoint=%s insecure=%v", cfg.Endpoint, cfg.Insecure)
	host, _ := os.Hostname()
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName("mna"),
			attribute.String("netagent.hostname", host),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("resource: %w", err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	return tp, nil
}

type commCacheEntry struct {
	comm   string
	expire time.Time
}

// commCache is a tiny TTL cache to avoid reading /proc/<pid>/comm on every event.
type commCache struct {
	data map[uint32]commCacheEntry
}

func newCommCache() *commCache {
	return &commCache{data: make(map[uint32]commCacheEntry, 128)}
}

func (c *commCache) get(pid uint32) (string, bool) {
	if e, ok := c.data[pid]; ok {
		if time.Now().Before(e.expire) {
			return e.comm, true
		}
		delete(c.data, pid)
	}
	return "", false
}

func (c *commCache) set(pid uint32, comm string) {
	c.data[pid] = commCacheEntry{comm: comm, expire: time.Now().Add(commCacheTTL)}
}

func main() {
	var cfgPath string
	flag.StringVar(&cfgPath, "config", "config.yaml", "path to config yaml")
	flag.Parse()

	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	tp, err := setupTracer(context.Background(), cfg.Otel)
	if err != nil {
		log.Fatalf("otel setup: %v", err)
	}
	if tp != nil {
		defer func() { _ = tp.Shutdown(context.Background()) }()
	}
	tracer := otel.Tracer("mna")
	tracingEnabled := tp != nil

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("warn: unable to raise memlock rlimit: %v (proceeding; ensure ulimit -l is sufficient)", err)
	}

	var l ebpf.Loader
	if err := l.LoadAndAttach(); err != nil {
		log.Fatalf("ebpf attach: %v", err)
	}
	defer l.Close()

	rd, err := ringbuf.NewReader(l.Objects.Events)
	if err != nil {
		log.Fatalf("ringbuf reader: %v", err)
	}
	defer rd.Close()

	allowed := map[string]string{} // comm -> logical name
	for _, t := range cfg.Targets {
		if t.MatchComm != "" {
			allowed[t.MatchComm] = t.Name
		}
	}
	if len(allowed) == 0 {
		log.Printf("warning: empty allow list; no events will be counted (check config.targets)")
	}

	var matched uint64
	var skipped uint64
	var readErrors uint64
	var txDurations uint64
	var spansStarted uint64

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	srv := &http.Server{Addr: cfg.Export.ListenAddr, Handler: mux}
	cache := newCommCache()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf("metrics on %s/metrics", cfg.Export.ListenAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http: %v", err)
		}
	}()

	go func() {
		for {
			rec, err := rd.Read()
			if err != nil {
				atomic.AddUint64(&readErrors, 1)
				log.Printf("ringbuf read error (matched=%d skipped=%d): %v", atomic.LoadUint64(&matched), atomic.LoadUint64(&skipped), err)
				return
			}
			var e event
			if len(rec.RawSample) < binary.Size(e) {
				continue
			}
			if err := binary.Read(bytesReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
				continue
			}

			comm, ok := cache.get(e.Pid)
			if !ok {
				var err error
				comm, err = pidComm(e.Pid)
				if err != nil {
					continue
				}
				cache.set(e.Pid, comm)
			}
			proto := protoStr(e.Proto)
			procName, ok := allowed[comm]
			if !ok {
				sc := atomic.AddUint64(&skipped, 1)
				if sc <= 5 || sc%100 == 0 {
					log.Printf("skipping comm=%q proto=%s dport=%d (not in config.targets)", comm, proto, e.Dport)
				}
				continue
			}

			atomic.AddUint64(&matched, 1)
			dstIP := ""
			srcIP := ""
			if e.Family == 2 { // AF_INET
				dstIP = ip4(e.Daddr)
				srcIP = ip4(e.Saddr)
			}

			switch e.Op {
			case opConnect:
				m.Connects.WithLabelValues(procName, proto, strconv.Itoa(int(e.Dport)), dstIP).Inc()
				if dstIP != "" {
					m.EdgeTotal.WithLabelValues(procName, proto, strconv.Itoa(int(e.Dport)), dstIP).Inc()
				}
			case opTxDuration:
				atomic.AddUint64(&txDurations, 1)
				sec := float64(e.DurationNs) / 1e9
				m.TxDuration.WithLabelValues(procName, proto, strconv.Itoa(int(e.Dport)), dstIP).Observe(sec)

				if tracingEnabled && tracer != nil && dstIP != "" {
					parent, flowID, hasFlow := flowTraceContext(srcIP, e.Sport, dstIP, e.Dport, proto)
					ctx := context.Background()
					if hasFlow {
						ctx = trace.ContextWithRemoteSpanContext(ctx, parent)
					}
					start := time.Now().Add(-time.Duration(e.DurationNs))
					_, span := tracer.Start(ctx, fmt.Sprintf("%s -> %s:%d (%s)", procName, dstIP, e.Dport, proto), trace.WithTimestamp(start))
					attrs := []attribute.KeyValue{
						attribute.String("process", procName),
						attribute.String("proto", proto),
						attribute.String("dport", strconv.Itoa(int(e.Dport))),
						attribute.String("dst_ip", dstIP),
					}
					if e.Sport != 0 {
						attrs = append(attrs, attribute.String("sport", strconv.Itoa(int(e.Sport))))
					}
					if srcIP != "" {
						attrs = append(attrs, attribute.String("src_ip", srcIP))
					}
					if e.Sk != 0 {
						attrs = append(attrs, attribute.String("socket", fmt.Sprintf("0x%x", e.Sk)))
					}
					if hasFlow {
						attrs = append(attrs, attribute.String("flow_id", flowID))
					}
					span.SetAttributes(attrs...)
					span.End(trace.WithTimestamp(start.Add(time.Duration(e.DurationNs))))
					atomic.AddUint64(&spansStarted, 1)
				}
			default:
				// ignore unknown op
			}
		}
	}()

	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for range t.C {
			mc := atomic.LoadUint64(&matched)
			sc := atomic.LoadUint64(&skipped)
			rc := atomic.LoadUint64(&readErrors)
			dc := atomic.LoadUint64(&txDurations)
			sp := atomic.LoadUint64(&spansStarted)
			log.Printf("events matched=%d skipped_no_match=%d read_errors=%d tx_durations=%d spans_started=%d", mc, sc, rc, dc, sp)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)

	// Ensure goroutines drain before exit during tests.
	runtime.Gosched()
}

type byteReader struct {
	b []byte
	i int
}

func bytesReader(b []byte) *byteReader {
	return &byteReader{b: b}
}

func (r *byteReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, fmt.Errorf("eof")
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}
