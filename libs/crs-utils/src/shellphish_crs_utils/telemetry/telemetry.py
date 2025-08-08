from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS
import os
import socket
from enum import Enum
from typing import Optional

from .enums import EVENTS

hostname = socket.gethostname()

# InfluxDB initialization
bucket = os.getenv("INFLUXDB_BUCKET", "artiphishell")
org = os.getenv("INFLUXDB_ORG", "artiphishell")
token = os.getenv("INFLUXDB_TOKEN", "shellphish-influxdb-token")
url = os.getenv("INFLUXDB_URL", None)

if url is not None:
    try:
        client = InfluxDBClient(url=url, token=token, org=org)
        client.api_client.configuration.timeout = 5 * 1000  # 5 seconds

        write_api = client.write_api(write_options=SYNCHRONOUS)
        query_api = client.query_api()
        is_available = client.health().status != "fail"
    except ValueError as e:
        print(f"Failed to connect to InfluxDB: {e}")
        is_available = False
else:
    is_available = False
    print("No INFLUXDB_URL found, telemetry is disabled")


def ensure_client(func):
    def wrapper(*args, **kwargs):
        if not is_available:
            return None
        return func(*args, **kwargs)

    return wrapper


class Telemetry:
    __COMPONENT_NAME__ = "Telemetry"

    @classmethod
    @ensure_client
    def log_component_event(
        cls, event: EVENTS, value=None, message=None
    ) -> Optional[Point]:
        if not is_available:
            print(
                f"InfluxDB is not available, skipping telemetry, url: {url}, event: {event}, value: {value}, message: {message}"
            )
            return

        point = None
        try:
            cmp_name = cls.__COMPONENT_NAME__
            cmp_id = os.environ.get("JOB_ID", "UNKNOWN")
            cmp_rep_id = int(os.environ.get("REPLICA_ID", 0))

            # Log the event
            event_val = event.value if isinstance(event, Enum) else str(event)

            point = (
                Point("component_event")
                .tag("component_id", cmp_id)
                .tag("component_name", cmp_name)
                .tag("replica_id", cmp_rep_id)
                .tag("hostname", hostname)
            )

            if message:
                point.field("message", message)

            if value:
                point.field(event_val, value)

            write_api.write(bucket=bucket, org=org, record=point)
        except Exception as e:
            print(f"Failed to log component event: {e}")
            # print(traceback.format_exc())
        return point

    @classmethod
    @ensure_client
    def log_component_start(cls):
        cls.log_component_event(
            event=EVENTS.COMPONENT_START,
            value=1,
            message=f"{cls.__COMPONENT_NAME__} started",
        )

    @classmethod
    @ensure_client
    def log_component_finish(cls):
        cls.log_component_event(
            event=EVENTS.COMPONENT_FINISH,
            value=-1,
            message=f"{cls.__COMPONENT_NAME__} finished",
        )

    @classmethod
    @ensure_client
    def log_component_error(cls, error_message: str):
        cls.log_component_event(
            event=EVENTS.COMPONENT_ERROR, value=0, message=error_message
        )

    @staticmethod
    @ensure_client
    def task_status() -> dict[str, int]:
        """
        Returns the number of tasks in each status.

        Returns:
            Dict[str, int]: The number of tasks in each status.
        """
        task_status = {
            "START": 0,
            "FINISH": 0,
            "ERROR": 0,
            "PENDING": 0,
            "CANCELLED": 0,
        }
        for event in task_status.keys():
            query = f'''from(bucket: "{bucket}")
            |> range(start: 0) 
            |> filter(fn: (r) => r["component_name"] == "Challenge Project")
            |> filter(fn: (r) => r["_field"] == "{event}")
            |> group()
            |> count()
            |> yield(name: "count")
            '''
            result = query_api.query(query)
            if len(result) == 0:
                task_status[event] = 0
            else:
                task_status[event] = result[0].records[0].get_value()

        return task_status

    @staticmethod
    @ensure_client
    def get_llm_cost_by_component() -> dict[str, float]:
        """
        Returns the total cost of the LLM for all components.
        """
        old_timeout = client.api_client.configuration.timeout
        client.api_client.configuration.timeout = 600 * 1000  # 10 minutes

        query = f'''
        import "strings"
        import "experimental/json"

        from(bucket: "{bucket}")
            |> range(start: 0)
            |> filter(fn: (r) => r["_measurement"] == "spans")
            |> filter(fn: (r) => r["_field"] == "attributes")
            |> filter(fn: (r) => strings.containsStr(substr: "gen_ai.usage.cost", v: r._value) == true)
            |> map(fn: (r) => {{
                jsonData = json.parse(data: bytes(v: r._value))
                return {{
                    _time: r._time,
                    _field: r["service.name"],
                    _value: jsonData["gen_ai.usage.cost"],

                }}
            }},)
            |> group(columns: ["_field"])
            |> sum(column: "_value")
        '''
        result = query_api.query(query)
        if len(result) == 0:
            return {}

        client.api_client.configuration.timeout = old_timeout
        return {r.get_field(): r.get_value() for group in result for r in group.records}

    @staticmethod
    @ensure_client
    def get_llm_cost_by_user(time_start: int = 0) -> dict[str, float]:
        """
        Returns the total cost of the LLM for all users.
        Args:
            time_start (int): The start time of the query in seconds since epoch. Defaults to 0.
        """
        old_timeout = client.api_client.configuration.timeout
        client.api_client.configuration.timeout = 600 * 1000  # 10 minutes

        query = f'''
import "strings"
import "experimental/json"

raw = from(bucket: "artiphishell")
            |> range(start: 0)
            |> filter(fn: (r) => r["_measurement"] == "spans")
            |> filter(fn: (r) => r["_field"] == "attributes")
            |> filter(fn: (r) => strings.containsStr(substr: "gen_ai.usage.cost", v: r._value) == true)
            |> map(fn: (r) => {{
                jsonData = json.parse(data: bytes(v: r._value))
                return {{
                    _time: r._time,
                    trace_id: r.trace_id,
                    _field: jsonData["gen_ai.request.user"],
                    _value: jsonData["gen_ai.usage.cost"],
                }}
            }},)

raw
            |> group(columns: ["trace_id"])
            |> reduce(
                  fn: (r, accumulator) => ({{
                        trace_id: r.trace_id,
                        _field:     if r._field != "" then r._field else accumulator._field,
                        _value:     r._value + accumulator._value,
                        _time:    if r._time > accumulator._time then r._time else accumulator._time
                  }}),
                  identity:{{_field:"", _value:0.0, _time:time(v:0), trace_id: "0"}})
            |> group(columns: ["_field"])
            |> sum(column: "_value")
        '''
        result = query_api.query(query)
        if len(result) == 0:
            return {}

        client.api_client.configuration.timeout = old_timeout
        return {r.get_field(): r.get_value() for group in result for r in group.records}


    @staticmethod
    @ensure_client
    def get_llm_cost_by_pdt_id(pdt_id: str) -> float:
        """
        Returns the total cost of the LLM for a specific PDT ID.
        """
        old_timeout = client.api_client.configuration.timeout
        client.api_client.configuration.timeout = 10 * 1000  # 10 minutes

        query = f'''
        import "strings"
        import "experimental/json"

        from(bucket: "{bucket}")
        |> range(start: 0)
        |> filter(fn: (r) => r["_measurement"] == "spans")
        |> filter(fn: (r) => r["service.name"] == "patcherq")
        |> filter(fn: (r) => r["_field"] == "attributes")
        |> filter(fn: (r) => strings.containsStr(substr: "{pdt_id}", v: r._value) == true)
        |> filter(fn: (r) => strings.containsStr(substr: "gen_ai.usage.cost", v: r._value) == true)
        |> map(fn: (r) => {{
            data = json.parse(data: bytes(v: r._value))
            return {{
                name: r["service.name"],
                _field: "cost",
                _value: data["gen_ai.usage.cost"]
            }}
        }})
        |> sum(column: "_value")
        '''
        result = query_api.query(query)
        if len(result) == 0:
            return -1.0

        client.api_client.configuration.timeout = old_timeout
        return result[0].records[0].get_value()