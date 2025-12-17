cmake_minimum_required(VERSION 3.16)
project(netagent_otel_cpp_client LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(opentelemetry-cpp CONFIG REQUIRED COMPONENTS exporters_otlp_grpc trace)

add_executable(otel_cpp_client main.cpp)
target_link_libraries(otel_cpp_client PRIVATE opentelemetry_trace opentelemetry_exporter_otlp_grpc)
