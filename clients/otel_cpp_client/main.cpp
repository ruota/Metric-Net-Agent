#include <chrono>
#include <cstdlib>
#include <iostream>
#include <string>

#include "opentelemetry/exporters/otlp/otlp_grpc_exporter.h"
#include "opentelemetry/exporters/otlp/otlp_grpc_exporter_options.h"
#include "opentelemetry/sdk/resource/resource.h"
#include "opentelemetry/sdk/trace/simple_processor.h"
#include "opentelemetry/sdk/trace/tracer_provider.h"
#include "opentelemetry/trace/provider.h"
#include "opentelemetry/trace/scope.h"

namespace otel    = opentelemetry;
namespace trace   = otel::trace;
namespace sdktrace = otel::sdk::trace;
namespace resource = otel::sdk::resource;
namespace exporter = otel::exporter::otlp;

static std::string env_or(const char *name, const std::string &def) {
  const char *v = std::getenv(name);
  return v ? std::string(v) : def;
}

int main() {
  // Config via env vars
  const std::string endpoint = env_or("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317");
  const std::string process = env_or("NETAGENT_PROCESS", "netagent-cpp");
  const std::string proto = env_or("NETAGENT_PROTO", "tcp");
  const std::string dst_ip = env_or("NETAGENT_DST_IP", "127.0.0.1");
  const std::string dst_port = env_or("NETAGENT_DST_PORT", "80");
  const double duration_ms = std::stod(env_or("NETAGENT_DURATION_MS", "50"));

  exporter::OtlpGrpcExporterOptions opts;
  opts.endpoint = endpoint;
  opts.use_ssl_credentials = false;  // plaintext by default

  auto exporter = std::make_unique<exporter::OtlpGrpcExporter>(opts);
  auto processor = std::make_unique<sdktrace::SimpleSpanProcessor>(std::move(exporter));

  auto res = resource::Resource::Create(
      {otel::common::AttributeValue("service.name"), otel::common::AttributeValue("netagent-cpp-client")});

  auto provider = std::make_shared<sdktrace::TracerProvider>(std::move(processor), res);
  trace::Provider::SetTracerProvider(provider);
  auto tracer = provider->GetTracer("netagent-cpp-client");

  const auto start = std::chrono::system_clock::now();
  trace::StartSpanOptions opts_start;
  opts_start.start_time = start;

  auto span = tracer->StartSpan(process + " -> " + dst_ip + ":" + dst_port + " (" + proto + ")", {}, opts_start);
  span->SetAttribute("process", process);
  span->SetAttribute("proto", proto);
  span->SetAttribute("dst_ip", dst_ip);
  span->SetAttribute("dport", dst_port);

  // Simulated duration without sleeping.
  const auto end = start + std::chrono::milliseconds(static_cast<long>(duration_ms));
  span->End(end);

  // Flush and shutdown tracer provider
  provider->ForceFlush();
  provider->Shutdown();

  std::cout << "Sent span to OTLP endpoint " << endpoint << " for " << process << " -> "
            << dst_ip << ":" << dst_port << " proto=" << proto
            << " duration_ms=" << duration_ms << std::endl;
  return 0;
}
