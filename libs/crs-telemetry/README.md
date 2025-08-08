# CRS Telemetry

A library for telemetry and observability via OpenTelemetry in the ARTIPHISHELL CRS (Cyber Reasoning System) framework.

## Overview

This library provides OpenTelemetry integration for the CRS framework, enabling distributed tracing, logging, and metrics collection. It supports both programmatic usage and CLI-based telemetry operations.

## Installation

```bash
pip install crs-telemetry
```

## Dependencies

- Python >= 3.10
- OpenTelemetry packages
- openlit
- agentlib
- crs-utils (optional but recommended)

## Environment Variables

The library uses several environment variables for configuration:

- `OTEL_EXPORTER_OTLP_ENDPOINT`: The endpoint for the OpenTelemetry collector
- `OTEL_DEBUG`: Enable debug mode for console output
- `JOB_ID`: Unique identifier for the job
- `REPLICA_ID`: Identifier for the replica instance
- `TASK_NAME`: Name of the current task
- `PROJECT_ID`: Project identifier for metadata collection

## Usage

### Programmatic Usage

1. Initialize OpenTelemetry:

```python
from crs_telemetry.utils import init_otel, init_llm_otel

# Initialize with component name and action details
init_otel(
    name="my_component",
    crs_action_category="static_analysis",  # or other valid categories
    crs_action_name="analyze_target"
)
init_llm_otel(name="my_component") #If your task uses llms at all, otherwise this is unneeded

```

2. Get a tracer and create spans:

```python
from crs_telemetry.utils import get_otel_tracer, get_current_span

# Get a tracer
tracer = get_otel_tracer("my_component")

# Create a span
with tracer.start_as_current_span("operation_name") as span:
    # Your code here
    span.set_attribute("key", "value")
```

3. Get current span and set status:

```python
from crs_telemetry.utils import get_current_span, status_ok, status_error

span = get_current_span()
span.set_status(status_ok())  # or status_error()
```

### CLI Usage

The library provides a CLI tool `telemetry-cli` with several commands:

1. Start a new span:
```bash
telemetry-cli start <name> <category> <action_name> <span_name> [options]
```

Options:
- `--parent-span-id`: Parent span ID (hex)
- `--trace-id`: Trace ID (hex)
- `--attributes`: JSON string of attributes
- `--links`: JSON string array of [trace_id, span_id] for links
- `--start-time`: Start time in nanoseconds

2. End a span:
```bash
telemetry-cli end <span_id> [options]
```

Options:
- `--end-time`: End time in nanoseconds
- `--status`: Final span status (ok/error)

3. List active spans:
```bash
telemetry-cli list
```

4. Show span lineage:
```bash
telemetry-cli lineage [--json]
```

5. Run a command within a span:
```bash
telemetry-cli run <name> <category> <action_name> <span_name> [options] <command>
```

Options:
- `--parent-span-id`: Parent span ID (hex)
- `--trace-id`: Trace ID (hex)
- `--attribute`: Add attribute in KEY=VALUE format (can be used multiple times)

6. Add attributes to a span:
```bash
telemetry-cli attributes <span_id> <attributes>
```

## Valid Categories

The following categories are supported for CRS actions:

- `static_analysis`
- `dynamic_analysis`
- `fuzzing`
- `program_analysis`
- `building`
- `input_generation`
- `patch_generation`
- `testing`
- `scoring_submission`

## Examples

1. Start a new span:
```bash
telemetry-cli start my_component static_analysis analyze_target "Main Analysis" --attributes '{"target": "example.c"}'
```

2. Run a command within a span:
```bash
telemetry-cli run my_component static_analysis analyze_target "Compilation" --attribute "compiler=gcc" gcc -o example example.c
```

3. End a span:
```bash
telemetry-cli end <span_id> --status ok
```

4. View span lineage:
```bash
telemetry-cli lineage
```

## Integration with Other Components

The library is designed to work with other CRS components and provides integration with:

- OpenTelemetry collector for distributed tracing
- Logging system for structured logs
- Metrics collection
- PDClient for metadata collection of the AIxCC Task (if crs-utils is installed)

## Health Checks

The library includes health checks for the OpenTelemetry collector. It will automatically check the collector's health endpoint when initializing telemetry.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. 