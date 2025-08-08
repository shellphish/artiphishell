import argparse
import os
import tempfile
import pathlib
import json
import time

from typing import Dict, Union, Optional, get_args

import opentelemetry.trace as trace
from opentelemetry.trace import (
    Tracer,
    Span,
    Status,
    StatusCode,
    SpanContext,
    SpanKind,
    TraceFlags,
    NonRecordingSpan,
    Link,
)

from crs_telemetry.utils import (
    get_otel_tracer,
    init_otel,
    CategoryType,
    is_healthy,
)

# A simple in-memory storage for active spans (used within a process)
_ACTIVE_SPANS: Dict[str, Dict[str, Union[Span, int, str, dict]]] = {}

# Environment variables for tracking spans across processes
OTEL_TRACE_ID_ENV = "OTEL_TRACE_ID"
OTEL_PARENT_SPAN_ID_ENV = "OTEL_PARENT_SPAN_ID"
OTEL_CURRENT_SPAN_ID_ENV = "OTEL_CURRENT_SPAN_ID"
OTEL_SPAN_NAME_ENV = "OTEL_SPAN_NAME"
OTEL_SPAN_STORAGE_DIR_ENV = "OTEL_SPAN_STORAGE_DIR"

# Default storage directory for span information
DEFAULT_SPAN_STORAGE_DIR = os.path.join(tempfile.gettempdir(), "otel_spans")

# Ensure the storage directory exists
os.makedirs(
    os.environ.get(OTEL_SPAN_STORAGE_DIR_ENV, DEFAULT_SPAN_STORAGE_DIR), exist_ok=True
)


def hex_str_to_int(hex_str: str) -> int:
    """Convert a hex string to an integer."""
    if not hex_str:
        return 0
    try:
        return int(hex_str, 16)
    except ValueError:
        return 0


def int_to_hex_str(value: int) -> str:
    """Convert an integer to a hex string."""
    if not value:
        return "0" * 16
    return format(value, "016x")


def get_span_storage_path(span_id: str) -> str:
    """Get the file path for storing span information."""
    storage_dir = os.environ.get(OTEL_SPAN_STORAGE_DIR_ENV, DEFAULT_SPAN_STORAGE_DIR)
    return os.path.join(storage_dir, f"span_{span_id}.json")


def store_span_info(
    span_id: str,
    trace_id: str,
    parent_span_id: Optional[str],
    name: str,
    start_time: int,
    attributes: Optional[dict] = None,
    links: Optional[list] = None,
) -> None:
    """Store span information in a file for persistence across processes."""
    span_info = {
        "span_id": span_id,
        "trace_id": trace_id,
        "parent_span_id": parent_span_id,
        "name": name,
        "start_time": start_time,
        "attributes": attributes or {},
        "links": links or [],
        "status": "active",
    }

    with open(get_span_storage_path(span_id), "w") as f:
        json.dump(span_info, f)


def load_span_info(span_id: str) -> Optional[dict]:
    """Load span information from storage."""
    file_path = get_span_storage_path(span_id)
    if os.path.exists(file_path):
        try:
            with open(file_path, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return None


def update_span_status(
    span_id: str, status: str, end_time: Optional[int] = None
) -> bool:
    """Update the status of a stored span."""
    span_info = load_span_info(span_id)
    if span_info:
        span_info["status"] = status
        if end_time:
            span_info["end_time"] = end_time

        with open(get_span_storage_path(span_id), "w") as f:
            json.dump(span_info, f)
        return True
    return False


def list_stored_spans() -> Dict[str, dict]:
    """List all spans from the persistent storage."""
    storage_dir = os.environ.get(OTEL_SPAN_STORAGE_DIR_ENV, DEFAULT_SPAN_STORAGE_DIR)
    result = {}

    # List all span files in the storage directory
    span_files = pathlib.Path(storage_dir).glob("span_*.json")

    for file_path in span_files:
        try:
            with open(file_path, "r") as f:
                span_info = json.load(f)
                if span_info and "span_id" in span_info:
                    result[span_info["span_id"]] = span_info
        except (json.JSONDecodeError, IOError):
            continue

    return result


def find_active_spans() -> Dict[str, dict]:
    """Find all active spans from the persistent storage."""
    all_spans = list_stored_spans()
    return {
        span_id: info
        for span_id, info in all_spans.items()
        if info.get("status") == "active"
    }


def create_span_with_context(
    tracer: Tracer,
    name: str,
    parent_span_id: Optional[str] = None,
    trace_id: Optional[str] = None,
    kind: SpanKind = SpanKind.INTERNAL,
    attributes: Optional[dict] = None,
    links: Optional[list] = None,
    start_time: Optional[int] = None,
) -> tuple[Span, str, str]:
    """
    Create a span with specific context parameters.

    Args:
        tracer: The tracer to use
        name: Name of the span
        parent_span_id: Optional hex string of the parent span ID
        trace_id: Optional hex string of the trace ID
        kind: The SpanKind
        attributes: Optional attributes to add to the span
        links: Optional list of [trace_id, span_id, trace_state] for linked spans
        start_time: Optional start time in nanoseconds since epoch

    Returns:
        tuple (span, span_id, trace_id) - The created span, its ID and trace ID as hex strings
    """
    parent_ctx = None
    span_links = []

    # Process span links if provided
    if links:
        for link_info in links:
            if isinstance(link_info, list) and len(link_info) >= 2:
                link_trace_id = hex_str_to_int(link_info[0])
                link_span_id = hex_str_to_int(link_info[1])
                link_ctx = SpanContext(
                    trace_id=link_trace_id,
                    span_id=link_span_id,
                    is_remote=True,
                    trace_flags=TraceFlags(0x01),
                )
                span_links.append(Link(link_ctx))

    # If no trace_id provided but we have a parent span ID, try to get trace_id from parent
    if not trace_id and parent_span_id:
        parent_info = load_span_info(parent_span_id)
        if parent_info and "trace_id" in parent_info:
            trace_id = parent_info["trace_id"]

    # If we have a trace_id from env var and no explicit trace_id provided, use the env var
    if not trace_id and OTEL_TRACE_ID_ENV in os.environ:
        trace_id = os.environ[OTEL_TRACE_ID_ENV]

    if trace_id or parent_span_id:
        # Convert hex strings to integers
        trace_id_int = hex_str_to_int(trace_id) if trace_id else None
        parent_span_id_int = hex_str_to_int(parent_span_id) if parent_span_id else None

        if trace_id_int:
            # Create a span context with the provided IDs
            span_context = SpanContext(
                trace_id=trace_id_int,
                span_id=parent_span_id_int if parent_span_id_int else 0,
                is_remote=True,
                trace_flags=TraceFlags(0x01),
            )
            parent_ctx = trace.set_span_in_context(NonRecordingSpan(span_context))

    # Create the span
    span = tracer.start_span(
        name=name,
        context=parent_ctx,
        kind=kind,
        attributes=attributes,
        links=span_links if span_links else None,
        start_time=start_time,
    )

    # Generate a unique ID for this span
    span_id = int_to_hex_str(span.get_span_context().span_id)
    actual_trace_id = int_to_hex_str(span.get_span_context().trace_id)

    # Store the span in our dictionary with metadata
    _ACTIVE_SPANS[span_id] = {
        "span": span,
        "name": name,
        "trace_id": actual_trace_id,
        "parent_span_id": parent_span_id,
        "start_time": int(time.time() * 1_000_000_000)
        if start_time is None
        else start_time,
    }

    # Store span info in persistent storage
    store_span_info(
        span_id=span_id,
        trace_id=actual_trace_id,
        parent_span_id=parent_span_id,
        name=name,
        start_time=int(time.time() * 1_000_000_000)
        if start_time is None
        else start_time,
        attributes=attributes,
        links=[
            {"trace_id": link.context.trace_id, "span_id": link.context.span_id}
            for link in (span_links or [])
        ],
    )

    return span, span_id, actual_trace_id


def end_span(span_id: str, end_time: Optional[int] = None, status: str = "ok") -> bool:
    """
    End a span by its ID.

    Args:
        span_id: The hex string ID of the span to end
        end_time: Optional end time in nanoseconds since epoch
        status: Status to set for the span (ok or error)

    Returns:
        True if the span was found and ended, False otherwise
    """
    # End the span if it's in memory
    end_time = int(time.time() * 1_000_000_000) if end_time is None else end_time
    if span_id in _ACTIVE_SPANS:
        span_info = _ACTIVE_SPANS[span_id]
        span = span_info["span"]
        if status == "error":
            span.set_status(Status(StatusCode.ERROR))
        else:
            span.set_status(Status(StatusCode.OK))
        span.end(end_time=end_time)
        _ACTIVE_SPANS.pop(span_id)

    # Update the span status in storage
    span_updated = update_span_status(span_id, status=status, end_time=end_time)

    # Clean up environment variables if this is the current span
    env_span_info = get_current_span_info()
    if env_span_info.get("span_id") == span_id:
        # If there's a parent span ID in the environment, restore it as the current span
        parent_span_id = env_span_info.get("parent_span_id")
        trace_id = env_span_info.get("trace_id")

        if parent_span_id:
            # Get parent span info to restore its name
            parent_info = find_span_by_id(parent_span_id)
            parent_name = parent_info.get("name") if parent_info else None

            # Restore parent as current, without a parent (becoming the top of the hierarchy)
            set_current_span_env(
                trace_id=trace_id, span_id=parent_span_id, span_name=parent_name
            )
        else:
            # No parent, clear all environment variables
            if OTEL_TRACE_ID_ENV in os.environ:
                del os.environ[OTEL_TRACE_ID_ENV]
            if OTEL_CURRENT_SPAN_ID_ENV in os.environ:
                del os.environ[OTEL_CURRENT_SPAN_ID_ENV]
            if OTEL_PARENT_SPAN_ID_ENV in os.environ:
                del os.environ[OTEL_PARENT_SPAN_ID_ENV]
            if OTEL_SPAN_NAME_ENV in os.environ:
                del os.environ[OTEL_SPAN_NAME_ENV]

    return span_updated


def find_span_by_id(span_id: str) -> Optional[dict]:
    """
    Find a span's information by its ID.

    Args:
        span_id: The hex string ID of the span

    Returns:
        Dictionary with span information or None if not found
    """
    # First check in-memory spans
    if span_id in _ACTIVE_SPANS:
        info = _ACTIVE_SPANS[span_id]
        return {k: v for k, v in info.items() if k != "span"}

    # Then check persistent storage
    return load_span_info(span_id)


def list_active_spans() -> Dict[str, dict]:
    """
    List all active spans (both in-memory and from storage).

    Returns:
        Dictionary of span IDs to their information
    """
    # Create a copy of in-memory spans without the actual span objects
    result = {}
    for span_id, info in _ACTIVE_SPANS.items():
        result[span_id] = {k: v for k, v in info.items() if k != "span"}

    # Add spans from persistent storage
    storage_spans = find_active_spans()
    for span_id, info in storage_spans.items():
        if span_id not in result:  # Don't overwrite in-memory spans
            result[span_id] = info

    return result


def get_current_span_info() -> Dict[str, str]:
    """
    Get information about the current span from environment variables.

    Returns:
        Dictionary with current span information
    """
    return {
        "trace_id": os.environ.get(OTEL_TRACE_ID_ENV, ""),
        "parent_span_id": os.environ.get(OTEL_PARENT_SPAN_ID_ENV, ""),
        "span_id": os.environ.get(OTEL_CURRENT_SPAN_ID_ENV, ""),
        "span_name": os.environ.get(OTEL_SPAN_NAME_ENV, ""),
    }


def discover_span_lineage() -> Dict[str, any]:
    """
    Discover the current parent span_id and trace_id, first checking environment variables,
    then resolve from files. Creates a linked list of spans where children point to parents.

    Returns:
        Dictionary with span lineage information including:
        - current: The current span info (if found)
        - trace_id: The trace ID (if found)
        - lineage: A list of span info objects organized from child to parent
    """
    result = {"current": None, "trace_id": None, "lineage": []}

    # Step 1: Try to get current span info from environment variables
    env_span_info = get_current_span_info()
    current_span_id = env_span_info.get("span_id")
    trace_id = env_span_info.get("trace_id")

    # If we don't have a current span ID from environment, try to find the most recent active span
    if not current_span_id:
        active_spans = list_active_spans()
        if active_spans:
            # Sort by start time to find the most recent span
            # This is a simple heuristic assuming the most recent span is likely the current one
            sorted_spans = sorted(
                active_spans.items(),
                key=lambda x: x[1].get("start_time", 0),
                reverse=True,
            )
            if sorted_spans:
                current_span_id = sorted_spans[0][0]
                span_info = sorted_spans[0][1]
                trace_id = span_info.get("trace_id")
                result["current"] = span_info
    else:
        # We have a span ID from environment, get its full info
        span_info = find_span_by_id(current_span_id)
        if span_info:
            result["current"] = span_info

    if not current_span_id:
        # Still no current span found
        return result

    # Step 2: Set the trace ID
    result["trace_id"] = trace_id

    # Step 3: Build the lineage (chain of parent spans)
    lineage = []
    span_id = current_span_id
    visited_spans = set()  # Prevent circular references

    while span_id and span_id not in visited_spans:
        visited_spans.add(span_id)
        span_info = find_span_by_id(span_id)

        if not span_info:
            break

        lineage.append(span_info)

        # Move to parent span
        span_id = span_info.get("parent_span_id")

    result["lineage"] = lineage
    return result


def get_current_context() -> Dict[str, str]:
    """
    Utility function to determine the current trace context.
    Used when no explicit parent_span_id or trace_id is provided.

    Returns:
        Dictionary with current trace context:
        - parent_span_id: The current span ID to use as parent (or None)
        - trace_id: The current trace ID (or None)
    """
    result = {"parent_span_id": None, "trace_id": None}

    # First try environment variables
    env_span_info = get_current_span_info()
    current_span_id = env_span_info.get("span_id")
    trace_id = env_span_info.get("trace_id")

    if current_span_id:
        result["parent_span_id"] = current_span_id
        result["trace_id"] = trace_id
        return result

    # If no environment variables, try to get from active spans
    active_spans = list_active_spans()
    if not active_spans:
        return result  # No spans found at all

    # Find the most recent active span
    sorted_spans = sorted(
        active_spans.items(), key=lambda x: x[1].get("start_time", 0), reverse=True
    )

    if sorted_spans:
        current_span_id = sorted_spans[0][0]
        span_info = sorted_spans[0][1]
        result["parent_span_id"] = current_span_id
        result["trace_id"] = span_info.get("trace_id")

    return result


def set_current_span_env(
    trace_id: str,
    span_id: str,
    parent_span_id: Optional[str] = None,
    span_name: Optional[str] = None,
) -> None:
    """
    Set environment variables for the current span.

    Args:
        trace_id: Trace ID as hex string
        span_id: Span ID as hex string
        parent_span_id: Optional parent span ID as hex string
        span_name: Optional span name
    """
    os.environ[OTEL_TRACE_ID_ENV] = trace_id
    os.environ[OTEL_CURRENT_SPAN_ID_ENV] = span_id

    if parent_span_id:
        os.environ[OTEL_PARENT_SPAN_ID_ENV] = parent_span_id
    elif OTEL_PARENT_SPAN_ID_ENV in os.environ:
        del os.environ[OTEL_PARENT_SPAN_ID_ENV]

    if span_name:
        os.environ[OTEL_SPAN_NAME_ENV] = span_name
    elif OTEL_SPAN_NAME_ENV in os.environ:
        del os.environ[OTEL_SPAN_NAME_ENV]


def otel_end(span_id: str, status: str = "ok"):
    end_time = int(time.time() * 1_000_000_000)

    if end_span(span_id, end_time, status):
        print(f"Span {span_id} ended successfully with status {status}")
    else:
        print(f"Span {span_id} not found")


def otel_lineage(json_format: bool = False):
    """Display the span lineage information."""
    lineage_info = discover_span_lineage()

    if json_format:
        # Return information as JSON
        print(json.dumps(lineage_info, indent=2))
        return

    # Format the output
    if not lineage_info["current"]:
        print("No current span found")
        return

    current_span = lineage_info["current"]
    trace_id = lineage_info["trace_id"]

    print(
        f"Current span: {current_span.get('name', 'unknown')} (ID: {current_span.get('span_id', 'unknown')})"
    )
    print(f"Trace ID: {trace_id or 'unknown'}")

    # Print the lineage as a tree
    print("\nSpan lineage (child → parent):")
    for i, span in enumerate(lineage_info["lineage"]):
        indentation = "  " * i
        print(
            f"{indentation}├─ {span.get('name', 'unknown')} (ID: {span.get('span_id', 'unknown')})"
        )
        # Print additional info
        if span.get("attributes"):
            print(
                f"{indentation}│  └─ Attributes: {json.dumps(span.get('attributes'), indent=2)}"
            )
        if span.get("links"):
            print(
                f"{indentation}│  └─ Links: {json.dumps(span.get('links'), indent=2)}"
            )


def otel_start(
    name: str,
    category: str,
    action_name: str,
    span_name: Optional[str] = None,
    parent_span_id: Optional[str] = None,
    trace_id: Optional[str] = None,
    links: Optional[str] = None,
    attributes: Optional[str] = None,
):
    if category not in get_args(CategoryType):
        print(f"Warning: '{category}' is not a recognized category")

    # Initialize OpenTelemetry
    init_otel(name, category, action_name)

    # Parse attributes if provided
    if attributes:
        try:
            attributes = json.loads(attributes)
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON for attributes: {attributes}")
            return

    # Parse links if provided
    if links:
        try:
            links = json.loads(links)
            if not isinstance(links, list):
                links = [links]
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON for links: {links}")
            return

    # If no parent_span_id or trace_id provided, try to get from current context
    if not parent_span_id or not trace_id:
        current_context = get_current_context()
        if not parent_span_id:
            parent_span_id = current_context["parent_span_id"]
        if not trace_id:
            trace_id = current_context["trace_id"]

    # Create the span
    start_time = int(time.time() * 1_000_000_000)
    span, span_id, trace_id = create_span_with_context(
        tracer=get_otel_tracer(name),
        name=span_name,
        parent_span_id=parent_span_id,
        trace_id=trace_id,
        attributes=attributes,
        links=links,
        start_time=start_time,
    )

    # Set environment variables for the current span
    set_current_span_env(
        trace_id=trace_id,
        span_id=span_id,
        parent_span_id=parent_span_id,
        span_name=span_name,
    )

    # Output the span ID
    result = {"span_id": span_id, "trace_id": trace_id}
    print(json.dumps(result))


def otel_run(
    name: str,
    category: str,
    action_name: str,
    command: list[str],
    span_name: Optional[str] = None,
    parent_span_id: Optional[str] = None,
    trace_id: Optional[str] = None,
    attributes: Optional[str] = None,
):
    if category not in get_args(CategoryType):
        print(f"Warning: '{category}' is not a recognized category")

    if span_name is None:
        span_name = f"{name}.{command[0]}"

    # If no parent_span_id or trace_id provided, try to get from current context
    if not parent_span_id or not trace_id:
        current_context = get_current_context()
        if not parent_span_id:
            parent_span_id = current_context["parent_span_id"]
        if not trace_id:
            trace_id = current_context["trace_id"]

    # Initialize OpenTelemetry
    init_otel(name, category, action_name)

    # Determine context for the span
    parent_ctx = None
    if parent_span_id:
        parent_span_id_int = hex_str_to_int(parent_span_id)
        trace_id_int = None

        if trace_id:
            trace_id_int = hex_str_to_int(trace_id)
        else:
            # Try to get trace ID from parent span
            parent_info = find_span_by_id(parent_span_id)
            if parent_info and "trace_id" in parent_info:
                trace_id_int = hex_str_to_int(parent_info["trace_id"])

        if trace_id_int:
            span_context = SpanContext(
                trace_id=trace_id_int,
                span_id=parent_span_id_int,
                is_remote=True,
                trace_flags=TraceFlags(0x01),
            )
            parent_ctx = trace.set_span_in_context(NonRecordingSpan(span_context))

    # Save current environment variables to restore later
    original_env_vars = {
        "trace_id": os.environ.get(OTEL_TRACE_ID_ENV),
        "span_id": os.environ.get(OTEL_CURRENT_SPAN_ID_ENV),
        "parent_span_id": os.environ.get(OTEL_PARENT_SPAN_ID_ENV),
        "span_name": os.environ.get(OTEL_SPAN_NAME_ENV),
    }

    # Create and run the span
    with get_otel_tracer(name).start_as_current_span(
        span_name, context=parent_ctx
    ) as span:
        # Get the span ID and trace ID
        span_id = int_to_hex_str(span.get_span_context().span_id)
        trace_id = int_to_hex_str(span.get_span_context().trace_id)
        for attribute in attributes or []:
            key = attribute.split("=")[0]
            value = "=".join(attribute.split("=")[1:])
            try:
                value = int(value)
            except ValueError:
                try:
                    value = float(value)
                except ValueError:
                    try:
                        value = json.loads(value)
                    except json.JSONDecodeError:
                        # If all conversions fail, use the string value
                        pass
            span.set_attribute(key, value)

        # Store span info
        store_span_info(
            span_id=span_id,
            trace_id=trace_id,
            parent_span_id=parent_span_id,
            name=span_name,
            start_time=int(time.time() * 1_000_000_000),
        )

        # Set environment variables for the command
        set_current_span_env(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            span_name=span_name,
        )

        # Output the span information
        print(json.dumps({"span_id": span_id, "trace_id": trace_id}))

        # Run the command
        if command:
            cmd = " ".join(command)
            exit_code = os.system(cmd)
        else:
            exit_code = 0

        # Update span status based on exit code
        status = "error" if exit_code != 0 else "ok"
        span.set_status(Status(StatusCode.ERROR if exit_code != 0 else StatusCode.OK))

        # Update span status in storage
        update_span_status(
            span_id=span_id, status=status, end_time=int(time.time() * 1_000_000_000)
        )

    # Restore original environment variables
    if original_env_vars["trace_id"]:
        os.environ[OTEL_TRACE_ID_ENV] = original_env_vars["trace_id"]
    elif OTEL_TRACE_ID_ENV in os.environ:
        del os.environ[OTEL_TRACE_ID_ENV]

    if original_env_vars["span_id"]:
        os.environ[OTEL_CURRENT_SPAN_ID_ENV] = original_env_vars["span_id"]
    elif OTEL_CURRENT_SPAN_ID_ENV in os.environ:
        del os.environ[OTEL_CURRENT_SPAN_ID_ENV]

    if original_env_vars["parent_span_id"]:
        os.environ[OTEL_PARENT_SPAN_ID_ENV] = original_env_vars["parent_span_id"]
    elif OTEL_PARENT_SPAN_ID_ENV in os.environ:
        del os.environ[OTEL_PARENT_SPAN_ID_ENV]

    if original_env_vars["span_name"]:
        os.environ[OTEL_SPAN_NAME_ENV] = original_env_vars["span_name"]
    elif OTEL_SPAN_NAME_ENV in os.environ:
        del os.environ[OTEL_SPAN_NAME_ENV]


def otel_add_attributes(span_id: str, attributes: str):
    span_info = find_span_by_id(span_id)
    if not span_info:
        print(f"Span {span_id} not found")
        return

    try:
        new_attrs = json.loads(attributes)

        # Update attributes in storage
        span_info["attributes"] = {**span_info.get("attributes", {}), **new_attrs}

        with open(get_span_storage_path(span_id), "w") as f:
            json.dump(span_info, f)

        # Also update in-memory span if available
        if span_id in _ACTIVE_SPANS and "span" in _ACTIVE_SPANS[span_id]:
            span = _ACTIVE_SPANS[span_id]["span"]
            for key, value in new_attrs.items():
                span.set_attribute(key, value)

        print(f"Attributes added to span {span_id}")

    except json.JSONDecodeError:
        print(f"Error: Invalid JSON for attributes: {attributes}")


def get_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="OpenTelemetry CLI Tool")
    subparsers = parser.add_subparsers(dest="utility", help="Commands")

    start_parser = subparsers.add_parser("start", help="Start a new span")
    start_parser.add_argument("name", type=str, help="Component name")
    start_parser.add_argument("category", type=str, help="CRS action category")
    start_parser.add_argument("action_name", type=str, help="CRS action name")
    start_parser.add_argument("span_name", type=str, help="Name of the span")
    start_parser.add_argument("--parent-span-id", type=str, help="Parent span ID (hex)")
    start_parser.add_argument("--trace-id", type=str, help="Trace ID (hex)")
    start_parser.add_argument(
        "--attributes", type=str, help="JSON string of attributes"
    )
    start_parser.add_argument(
        "--links", type=str, help="JSON string array of [trace_id, span_id] for links"
    )
    start_parser.add_argument(
        "--start-time", type=int, help="Start time in nanoseconds"
    )

    # "end" command for ending a span
    end_parser = subparsers.add_parser("end", help="End a span")
    end_parser.add_argument("span_id", type=str, help="Span ID to end (hex)")
    end_parser.add_argument("--end-time", type=int, help="End time in nanoseconds")
    end_parser.add_argument(
        "--status",
        type=str,
        choices=["ok", "error"],
        default="ok",
        help="Final span status",
    )

    # "list" command for listing active spans
    subparsers.add_parser("list", help="List active spans")

    # "lineage" command for discovering span lineage
    lineage_parser = subparsers.add_parser(
        "lineage", help="Discover and display span lineage"
    )
    lineage_parser.add_argument(
        "--json", action="store_true", help="Output lineage as JSON"
    )

    # "run" command for running a command within a span (similar to the original)
    run_parser = subparsers.add_parser("run", help="Run a command within a span")
    run_parser.add_argument("name", type=str, help="Component name")
    run_parser.add_argument("category", type=str, help="CRS action category")
    run_parser.add_argument("action_name", type=str, help="CRS action name")
    run_parser.add_argument("span_name", type=str, help="Name of the span")
    run_parser.add_argument("--parent-span-id", type=str, help="Parent span ID (hex)")
    run_parser.add_argument("--trace-id", type=str, help="Trace ID (hex)")
    run_parser.add_argument(
        "--attribute",
        action="append",
        dest="attributes",
        metavar="KEY=VALUE",
        help="Add attribute in KEY=VALUE format (can be used multiple times)",
    )
    run_parser.add_argument("command", nargs=argparse.REMAINDER, help="Command to run")

    # "attributes" command for adding attributes to a span
    attr_parser = subparsers.add_parser("attributes", help="Add attributes to a span")
    attr_parser.add_argument("span_id", type=str, help="Span ID to modify")
    attr_parser.add_argument("attributes", type=str, help="JSON string of attributes")

    # "create-shell-script" command for generating a shell script with tracing functions
    script_parser = subparsers.add_parser(
        "create-shell-script", help="Create a shell script with tracing functions"
    )
    script_parser.add_argument(
        "--output",
        type=str,
        default="otel_traces.sh",
        help="Output file path for the shell script",
    )

    args = parser.parse_args()
    if not args.utility:
        parser.print_help()
        exit(1)

    return args


def telemetry_cli():
    """
    Enhanced CLI for OpenTelemetry spans with ID management
    """
    if not is_healthy():
        return

    args = get_cli_args()

    if args.utility == "list":
        active_spans = list_active_spans()
        if active_spans:
            print(json.dumps(active_spans, indent=2))
        else:
            print("No active spans")

    elif args.utility == "lineage":
        json_format = args.json if hasattr(args, "json") else False
        otel_lineage(json_format)

    elif args.utility == "attributes":
        otel_add_attributes(args.span_id, args.attributes)

    elif args.utility == "start":
        otel_start(
            args.name,
            args.category,
            args.action_name,
            args.span_name,
            args.parent_span_id,
            args.trace_id,
        )

    elif args.utility == "end":
        otel_end(args.span_id, args.status)

    elif args.utility == "run":
        otel_run(
            args.name,
            args.category,
            args.action_name,
            args.command,
            args.span_name,
            args.parent_span_id,
            args.trace_id,
            args.attributes,
        )
