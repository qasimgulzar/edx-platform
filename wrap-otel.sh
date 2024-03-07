#!/bin/bash

export OTEL_PYTHON_LOGGING_AUTO_INSTRUMENTATION_ENABLED=true
export OTEL_SERVICE_NAME=tmccormack-local-dev
export OTEL_METRICS_EXPORTER=otlp
export OTEL_TRACES_EXPORTER=otlp
export OTEL_LOGS_EXPORTER=otlp
export OTEL_EXPORTER_OTLP_PROTOCOL=grpc
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317

opentelemetry-instrument "$@"

# opentelemetry-instrument --traces_exporter console --metrics_exporter console --logs_exporter console --service_name tmccormack-local-dev
