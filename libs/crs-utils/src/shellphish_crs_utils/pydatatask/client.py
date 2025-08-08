from enum import Enum
import hashlib
import itertools
import json
import logging
import os
from pathlib import Path
import random
import sys
import time
from typing import Any, Dict, List, Optional, Tuple, Union
import requests
from shellphish_crs_utils.models.base import ShellphishBaseModel
import yaml
from shellphish_crs_utils.models.pydatatask import PDTNodeInfo

LOG_FORMAT = (
    "%(asctime)s [%(levelname)-8s] "
    "%(name)s:%(lineno)d | %(message)s"
)
log = logging.getLogger(__name__)

class JobStatus(Enum):
    NOT_FOUND = "not found"
    RUNNING = "running"
    SUCCESS = "success"
    TIMEOUT = "timeout"
    FAILURE = "failure"


TASK_NAME = str
JOB_ID = str

class WhyReadyJobDataModel(ShellphishBaseModel):
    ready: bool
    live: bool
    require_success: bool
    fail_fast: bool
    failure_ok: bool
    long_running: bool
    project_id: Optional[str] = None
    job_id: JOB_ID
    task_name: TASK_NAME
    done: Optional[Dict] = None
    success: Optional[bool] = None
    timeout: Optional[bool] = None
    failure: Optional[bool] = None
    cancelled: bool

WhyReadyTaskDataModel = Dict[JOB_ID, WhyReadyJobDataModel]
WhyReadyDataModel = Dict[TASK_NAME, WhyReadyTaskDataModel]


class PDClient:
    def __init__(self, base_url: str, secret: str):
        """
        :param base_url: The root URL for your API, e.g. http://localhost:8080
        :param secret:   The secret value required by the server (set as a 'secret' cookie).
        """
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()

        # The server checks a "secret" cookie for authorization
        self.session.cookies.set("secret", secret)

    @staticmethod
    def from_local_pipeline_lock(pipeline_lock_path: Union[Path, str]) -> "PDClient":
        """
        Create a PDClient instance from a pipeline lock file.
        The lock file should be a YAML file with 'base_url' and 'secret' keys.
        """
        pipeline_lock_path = Path(pipeline_lock_path)
        with pipeline_lock_path.open("r") as f:
            lock_data = yaml.safe_load(f)
            return PDClient(f'http://localhost:{lock_data["agent_port"]}', lock_data["agent_secret"])

    @staticmethod
    def from_env() -> "PDClient":
        """
        Create a PDClient instance from the environment variables.
        The environment variables should be 'PD_BASE_URL' and 'PD_SECRET'.
        """
        agent_url = os.environ.get("PDT_AGENT_URL", None)
        if not agent_url:
            raise ValueError("PDT_AGENT_URL environment variable not set.")
        agent_secret = os.environ.get("PDT_AGENT_SECRET", None)
        if not agent_secret:
            raise ValueError("PDT_AGENT_SECRET environment variable not set.")
        return PDClient(
            base_url=agent_url,
            secret=agent_secret,
        )

    def health(self) -> str:
        """
        GET /health
        Returns the 'OK' string if healthy, or raises an exception on non-200 response.
        """
        url = f"{self.base_url}/health"
        r = self.session.get(url)
        r.raise_for_status()
        return r.text

    def status(self) -> Dict[str, int]:
        """
        GET /status/
        Returns the status JSON data as a dictionary with task counts.
        """
        url = f"{self.base_url}/status/"
        r = self.session.get(url)
        r.raise_for_status()
        return r.json()

    def get_data(self, task: str, link: str, job: str, meta: bool = False, out_file_path: str = None, subpath: str = None, allow_missing: bool = False) -> Optional[bytes]:
        """
        GET /data/{task}/{link}/{job}
        Optionally pass meta=True or subpath=some/path as query parameters.
        Returns the raw byte content from the response.
        """
        url = f"{self.base_url}/data/{task}/{link}/{job}"
        params = {}
        if meta:
            params["meta"] = "1"
        if subpath is not None:
            params["subpath"] = subpath

        r = self.session.get(url, params=params, stream=bool(out_file_path))
        if r.status_code == 404 and allow_missing:
            return None

        r.raise_for_status()
        if out_file_path:
            with open(out_file_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
            return out_file_path
        return r.content

    def why_ready(self, task=None, project_id=None) -> WhyReadyDataModel:
        """
        GET /why_ready
        Returns a dictionary of tasks and their jobs that are ready to run.
        """
        url = f"{self.base_url}/why_ready"
        params = {}
        if task:
            params["task"] = task
        if project_id:
            params["project_id"] = project_id

        r = self.session.get(url, params=params)
        r.raise_for_status()
        result = r.json()
        return {
            task_name: {
                job_id: WhyReadyJobDataModel.model_validate(job_info)
                for job_id, job_info in task_info.items()
            }
            for task_name, task_info in result.items()
        }

    def repo_keys(self, task: str, link: str, **kwargs) -> List[str]:
        """
        GET /keys/{task}/{link}
        Returns a list of keys for the given task and link.
        """
        url = f"{self.base_url}/keys/{task}/{link}"
        r = self.session.get(url)
        if r.status_code == 404 and 'default' in kwargs:
            return kwargs['default']
        r.raise_for_status()
        return r.json()

    def has_key(self, task: str, link: str, job: str) -> bool:
        """
        GET /data/{task}/{link}/{job}
        Returns True if the key exists, False otherwise.
        """
        # url = f"{self.base_url}/data/{task}/{link}/{job}"
        # r = self.session.head(url)
        # return r.status_code == 200
        return self.get_data(task, link, job, allow_missing=True) is not None

    def post_data(self, task: str, link: str, job: str, data: bytes, hostjob: str = None) -> str:
        """
        POST /data/{task}/{link}/{job}
        Sends 'data' as the request body. An optional hostjob can be provided as a query parameter.
        Returns the server's text response (the 'job' string if successful).
        """
        url = f"{self.base_url}/data/{task}/{link}/{job}"
        params = {}
        if hostjob is not None:
            params["hostjob"] = hostjob

        r = self.session.post(url, params=params, data=data)
        r.raise_for_status()
        return r.text

    def stream_data(self, task: str, link: str, job: str):
        """
        GET /stream/{task}/{link}/{job}
        Returns a generator that yields lines (decoded as UTF-8) from the streaming response.
        Usage example:
            for line in client.stream_data("mytask", "mylink", "myjob"):
                print("Streamed line:", line)
        """
        url = f"{self.base_url}/stream/{task}/{link}/{job}"
        with self.session.get(url, stream=True) as r:
            r.raise_for_status()
            for line in r.iter_lines(decode_unicode=True):
                if line:
                    yield line

    def query_job_status(self, task: str, job: str) -> Tuple[JobStatus, Dict]:
        """
        GET /status/{task}/{link}/{job}
        Returns the server's text response (the job status string).
        """
        live = yaml.safe_load(self.get_data(task, 'live', job))
        if live:
            return JobStatus.RUNNING, live

        done = yaml.safe_load(self.get_data(task, 'done', job))

        if not done:
            return JobStatus.NOT_FOUND, None

        if done['success']:
            return JobStatus.SUCCESS, done
        elif done['timeout']:
            return JobStatus.TIMEOUT, done
        else:
            return JobStatus.FAILURE, done

    def query(self, task: str, query_name: str, params: dict) -> bytes:
        """
        POST /query/{task}/{query}
        Sends 'params' as YAML in the request body.
        Returns the raw byte content from the response.
        """
        url = f"{self.base_url}/query/{task}/{query_name}"
        payload = yaml.dump(params)
        headers = {"Content-Type": "application/x-yaml"}

        r = self.session.post(url, data=payload.encode("utf-8"), headers=headers)
        r.raise_for_status()
        return r.content

    def post_cokey_data(self, task: str, link: str, cokey: str, job: str, data: bytes, hostjob: str = None) -> str:
        """
        POST /cokeydata/{task}/{link}/{cokey}/{job}
        Similar to post_data but for the co-key endpoint. Sends 'data' as the body.
        Optionally includes a 'hostjob' query param. Returns the server's text response.
        """
        url = f"{self.base_url}/cokeydata/{task}/{link}/{cokey}/{job}"
        params = {}
        if hostjob is not None:
            params["hostjob"] = hostjob

        r = self.session.post(url, params=params, data=data)
        r.raise_for_status()
        return r.text

    def get_errors(self, path: str = "") -> str:
        """
        GET /errors/{path:.*}
        Fetches any logged errors for the provided path.
        If path is empty, it retrieves /errors/.
        Returns the server's text response (may include error stack traces if any are logged).
        """
        # Make sure no leading slash is added accidentally by path
        path = path.lstrip("/")
        url = f"{self.base_url}/errors/{path}"
        r = self.session.get(url)
        r.raise_for_status()
        return r.text

    def get_nodes(self) -> List[PDTNodeInfo]:
        """
        GET /nodes
        Returns a list of nodes in the artiphishell cluster.
        """
        cur_node_ip = os.environ.get("NODE_IP", '127.0.0.1')
        url = f"{self.base_url}/nodes?node_ip={cur_node_ip}"
        r = self.session.get(url)
        r.raise_for_status()
        return [
            PDTNodeInfo.model_validate(node_info) for node_info in r.json()
        ]

    def get_nodes_to_sync(self, num_gossip_nodes: int = 2) -> List[PDTNodeInfo]:
        """
        Returns a subset of the nodes that the current node should sync with together with the current node itself.
        This currently selects a subset of the nodes based on the current node's IP address.
        Selection works as follows:
            1. Fetch all nodes from the cluster.
            2. Always return the self node (the current node).
            3. Sort the fuzzing nodes by the hash of their name + the current hour
                - This ensures that the selection is deterministic but changes every hour. So no single set of bad nodes will be selected repeatedly.
            4. Pick `num_gossip_nodes` random nodes from the fuzzing pool that aren't the current node or the previously selected two.
            5. Pick `num_gossip_nodes` random nodes from the non-fuzzing pool that aren't already selected.
            6. Remove duplicates and ensure we only have unique nodes.
            7. Return the selected nodes.

        This ensures two things:
            1. In the case of correct operation of the main fuzzing nodes, the syncing from the first and last is deterministic and the same
               for all nodes. This ensures that seeds and crashing inputs make it to the `merge` node in a maximum RTT of two sync intervals.
               (Three in the worst case of straddling the hour boundary).
               Each node then syncs its crashes and seeds from/to the first/last nodes, and then the next cycle the merge node syncs from there.
            2. In the case of main node fuzzing instance failure on some nodes but not others, step 4. above operates like a gossip protocol
               and ensures that the remaining nodes will eventually sync with the main fuzzing instance, and thus share their seeds and crashes
               as long as there are any functioning nodes still up and running.
            3. The non-fuzzing nodes are seperately synced from/to to ensure any seeds dumped by non-fuzzing components can be quickly picked
               up by the fuzzers.

        Returns:
            List of PDTNodeInfo objects representing the nodes that the current node should sync with.
            This will also include the `self` node always for completeness sake.
        """

        def node_sort_key(n: PDTNodeInfo) -> bytes:
            now = time.time()
            current_hour = int(now // 3600)
            # the hashing ensures that the selection is deterministic but uniformly distributed across all nodes.
            # if we were to just use the nodes or the IP, they would likely show patterns based on the spin-up time.
            to_hash = (n.name + str(current_hour)).encode('utf-8')
            hash = hashlib.md5(to_hash).digest()
            log.info(f"Hashing {n.name=} with {current_hour=} as {to_hash=} to {hash=}")
            return hash

        all_nodes = self.get_nodes()
        log.info(f"Found {len(all_nodes)} nodes in the cluster: {[n.name for n in all_nodes]}")
        # split nodes into self, fuzzing and non-fuzzing nodes

        fuzzing_nodes, non_fuzzing_nodes, self_nodes = [], [], []
        for n in all_nodes:
            if not n.ip:
                continue
            if n.self:
                self_nodes.append(n)
            elif '-fzz' in n.name: # fuzzing instances
                fuzzing_nodes.append(n)
            else:
                non_fuzzing_nodes.append(n)

        log.info(f"Found {len(fuzzing_nodes)} fuzzing nodes: {[n.name for n in fuzzing_nodes]}")
        log.info(f"Found {len(non_fuzzing_nodes)} non-fuzzing nodes: {[n.name for n in non_fuzzing_nodes]}")
        log.info(f"Found {len(self_nodes)} self nodes: {[n.name for n in self_nodes]}")

        if not self_nodes:
            log.error("No self node found in the cluster.")
            self_nodes = [
                PDTNodeInfo(name="node-fzz-self", ip=os.environ.get("NODE_IP", '127.0.0.1'), self=True, node_ip='127.0.0.1')  # Fallback if no self node is found
            ]

        sorted_fuzzing_nodes = list(sorted(fuzzing_nodes, key=node_sort_key))
        log.info(f"Sorted fuzzing nodes: {[n.name for n in sorted_fuzzing_nodes]}")

        nodes_to_sync = list(self_nodes)

        if len(fuzzing_nodes) >= 2 + num_gossip_nodes:
            log.info(f"We have {len(fuzzing_nodes)} fuzzing nodes >= 2 + {num_gossip_nodes} gossip nodes, selecting from them.")
            # first, pick the first and last fuzzing nodes and add them
            nodes_to_sync.extend([sorted_fuzzing_nodes[0], sorted_fuzzing_nodes[-1]])
            nodes_to_sync.extend(random.sample(
                [n for n in sorted_fuzzing_nodes[1:-1] if n not in nodes_to_sync],
                num_gossip_nodes,
            ))
        else:
            log.info(f"We have {len(fuzzing_nodes)} fuzzing nodes < 2 + {num_gossip_nodes} gossip nodes, selecting all fuzzing nodes.")
            nodes_to_sync.extend(fuzzing_nodes)

        if len(non_fuzzing_nodes) > num_gossip_nodes:
            # if there are more non-fuzzing nodes than gossip nodes, pick random ones
            log.info(f"We have {len(non_fuzzing_nodes)} non-fuzzing nodes > {num_gossip_nodes} gossip nodes, selecting from them.")
            nodes_to_sync.extend(random.sample(
                [n for n in non_fuzzing_nodes if n not in nodes_to_sync],
                num_gossip_nodes,
            ))
        else:
            # otherwise, just add all non-fuzzing nodes
            log.info(f"We have {len(non_fuzzing_nodes)} non-fuzzing nodes < {num_gossip_nodes} gossip nodes, selecting all non-fuzzing nodes.")
            nodes_to_sync.extend(non_fuzzing_nodes)

        log.info(f"Selected nodes to sync with: {[n.name for n in nodes_to_sync]}")

        # remove duplicates and ensure we only have unique nodes
        return list({n.name: n for n in nodes_to_sync}.values())

def get_nodes_to_sync():
    """
    This function is a convenience wrapper to get the nodes to sync with.
    It creates a PDClient instance from the pipeline environment variables and calls the get_nodes_to_sync method.
    """

    logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
    log.info("Fetching nodes to sync with...")
    # Parse command line arguments for num_gossip_nodes
    # This allows the user to specify how many gossip nodes they want to select.

    import argparse
    parser = argparse.ArgumentParser(description="Get nodes to sync with.")
    parser.add_argument("--num-gossip-nodes", type=int, default=2, help="Number of gossip nodes to select.")
    args = parser.parse_args()
    if args.num_gossip_nodes < 1:
        log.error("num_gossip_nodes must be at least 1.")
        raise ValueError("num_gossip_nodes must be at least 1.")
    if args.num_gossip_nodes > 10:
        log.error("num_gossip_nodes must be at most 10.")
        raise ValueError("num_gossip_nodes must be at most 10.")

    # Create a PDClient instance from environment variables
    # This assumes that the environment variables PDT_AGENT_URL and PDT_AGENT_SECRET are set
    # to the appropriate values for your PDClient instance.
    client = PDClient.from_env()

    nodes_to_sync = client.get_nodes_to_sync(num_gossip_nodes=args.num_gossip_nodes)
    assert any(n.self for n in nodes_to_sync), "No self node found in the selected nodes to sync with."
    log.info(f"Nodes to sync with (self node included): {[n.name for n in nodes_to_sync]}")
    print(json.dumps([n.model_dump() for n in nodes_to_sync], indent=2, sort_keys=True))
    sys.exit(0)
    # This function returns a JSON string of the nodes to sync with, including the self node.

# ------------------------------------------------------------------------
# Example usage:
#
# client = SimpleSynchronousClient("http://localhost:8080", secret="mysecret")
# print(client.health())               # "OK"
# data_bytes = client.get_data("task1", "linkA", "job123", meta=True)
# print("Data:", data_bytes)
#
# response_text = client.post_data("task1", "linkA", "job999", b"some binary content")
# print("POST response:", response_text)
#
# for line in client.stream_data("task1", "linkB", "jobXYZ"):
#     print("Stream line:", line)
#
# query_result = client.query("task1", "myquery", {"param1": "value1"})
# print("Query result (raw bytes):", query_result)
#
# cokey_resp = client.post_cokey_data("task1", "linkC", "cokeyA", "jobABC", b"co-keyed data")
# print("CoKey POST response:", cokey_resp)
#
# error_log = client.get_errors("data/task1/linkA/job999")
# print("Error log:", error_log)
