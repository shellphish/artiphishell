#! /usr/bin/env python3

import sys
import os
import argparse
import json
import logging
import subprocess
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Any, Optional

"""
The purpose of this script is to exec into each relivant node in the cluster
and delete data from /shared which is no longer relevant to the game

Here is how it will function:
- The script is called with a list of arguments.
  - One arg (flag) is the PROJECT_ID
  - Then there is a list of HARNESS_IDs (more than 1)
- Sanity check the provided IDs to make sure none of them are empty and they are all alphanumeric
- We get a list of nodes by querying the $PDT_AGENT_URL/nodes which returns a json list of nodes which are in scope for this cleanup
- We list all pods with label `name=host-config`
- There will be one pod per node. We filter down the pods to just the ones that are on nodes included in the list we got from the agent
- Then for each node, we exec into it and perform the cleanup step.

Cleanup Step:
For each node we need to do the following:
- rm -rf `/shared/<PROJECT_ID>` if any
- rm -rf `/shared/*/<PROJECT_ID>`
- rm -rf `/shared/fuzzer_sync/*<HARNESS_ID>` for each provided HARNESS_ID (note the wildcard expansion is important as the dirnames will have other junk before the HARNESS_ID)
- rm -rf `/shared/jazzer/fuzz/*<HARNESS_ID>` for each provided HARNESS_ID (note the wildcard expansion is important as the dirnames will have other junk before the HARNESS_ID)
- rm -rf `/shared/fuzzer_sync/*<HARNESS_ID>` for each provided HARNESS_ID (note the wildcard expansion is important as the dirnames will have other junk before the HARNESS_ID)
- rm -rf `/shared/libfuzzer/fuzz/*<HARNESS_ID>` for each provided HARNESS_ID (note the wildcard expansion is important as the dirnames will have other junk before the HARNESS_ID)

This cleanup should be done in a way that retries if there is a network issue doing the exec (the k8s api is unreliable and disconnects sometimes)

Also we should use some reasonable parallelism to speed up the cleanup as there may be 100s of nodes.

Nodes with `usr` in the name should be prioritized for cleanup and done first
"""

# -----------------------------------------------------------------------------
# Helper utilities
# -----------------------------------------------------------------------------

def _run(cmd: List[str]) -> Tuple[int, str, str]:
    """Run *cmd* returning (returncode, stdout, stderr).

    All output is captured as text and stripped of trailing whitespace for
    easier logging/handling.  This helper never raises.
    """
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def _http_get_json(url: str, timeout: int = 10) -> Any:
    """Fetch *url* and parse the response body as JSON."""
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.load(resp)


# -----------------------------------------------------------------------------
# Core logic
# -----------------------------------------------------------------------------

log = logging.getLogger(__name__)


class CleanupTask:
    """Represents the information required to clean a single node."""

    __slots__ = (
        "pod_name",
        "namespace",
        "node_name",
        "project_id",
        "harness_ids",
    )

    def __init__(
        self,
        pod_name: str,
        namespace: str,
        node_name: str,
        project_id: str,
        harness_ids: List[str],
    ) -> None:
        self.pod_name = pod_name
        self.namespace = namespace
        self.node_name = node_name
        self.project_id = project_id
        self.harness_ids = harness_ids

    # ------------------------------------------------------------------
    def run(self, max_retries: int = 3) -> bool:  # noqa: D401
        """Execute the cleanup for this node.  Returns True on success."""
        base_cmd = [
            "kubectl",
            "exec",
            "-n",
            self.namespace,
            self.pod_name,
            "--",
            "/bin/bash",
            "-c",
        ]
        assert self.project_id and self.project_id.strip() and self.project_id.isalnum()
        assert self.harness_ids and all(hid.strip() and hid.strip().isalnum() for hid in self.harness_ids)

        # Build remote shell command with proper escaping
        # Use bash for better glob support and escape harness IDs properly
        escaped_project_id = self.project_id.replace("'", "'\"'\"'")
        escaped_harness_ids = [hid.replace("'", "'\"'\"'") for hid in self.harness_ids]
        
        parts = [
            f"rm -rf '/shared/{escaped_project_id}' || true",
        ]

        parts.append(f"find /shared/ -maxdepth 3 -name '*{escaped_project_id}*' -type d -exec rm -rf {{}} \\; 2>/dev/null || true")
        
        # Handle fuzzer_sync cleanup with proper globbing
        for hid in escaped_harness_ids:
            # Use find to properly handle the globbing instead of shell expansion
            parts.append(f"find /shared/ -maxdepth 4 -name '*{hid}*' -type d -exec rm -rf {{}} \\; 2>/dev/null || true")
        
        remote_cmd = " && ".join(parts)

        cmd = base_cmd + [remote_cmd]
        
        log.debug("Executing cleanup command for node %s: %s", self.node_name, remote_cmd)

        for attempt in range(1, max_retries + 1):
            rc, out, err = _run(cmd)
            if rc == 0:
                log.info("✅  Cleaned %s (attempt %d)", self.node_name, attempt)
                if out:
                    log.debug("Cleanup output for %s: %s", self.node_name, out)
                return True
            else:
                log.warning(
                    "⚠️  Cleanup attempt %d/%d failed for %s: rc=%d, stderr=%s, stdout=%s",
                    attempt,
                    max_retries,
                    self.node_name,
                    rc,
                    err or "none",
                    out or "none",
                )
                # Exponential back-off between retries
                if attempt < max_retries:
                    sleep_time = min(2 ** attempt, 30)
                    log.debug("Retrying in %d seconds...", sleep_time)
                    time.sleep(sleep_time)
        
        log.error("❌  Failed to clean %s after %d attempts", self.node_name, max_retries)
        return False


# -----------------------------------------------------------------------------
# Data gathering helpers
# -----------------------------------------------------------------------------


def fetch_target_nodes(agent_url: str) -> List[str]:
    url = agent_url.rstrip("/") + "/nodes"
    try:
        data = _http_get_json(url)
    except Exception as exc:  # pylint: disable=broad-except
        log.error("Failed to fetch nodes from %s: %s", url, exc)
        sys.exit(1)

    if not isinstance(data, list):
        log.error("Unexpected JSON structure from %s: %s", url, data)
        sys.exit(1)

    # Parse the node objects and extract node names
    target_nodes = []
    for item in data:
        if item is None:
            continue
            
        # Handle case where API returns dict objects directly
        if isinstance(item, dict):
            node_name = item.get('name')
            if node_name:
                target_nodes.append(str(node_name).strip())
        else:
            # Handle case where API returns stringified dict objects
            item_str = str(item).strip()
            if not item_str:
                continue
                
            try:
                # Try to parse as Python literal (dict string)
                import ast
                parsed = ast.literal_eval(item_str)
                if isinstance(parsed, dict):
                    node_name = parsed.get('name')
                    if node_name and (
                        'storage' in node_name
                        or 'serv' in node_name
                        or 'crit' in node_name
                    ):
                        # Skip nodes that are storage, service, or critical
                        continue

                    if node_name:
                        target_nodes.append(str(node_name).strip())
                else:
                    # If it's not a dict, treat as raw node name
                    target_nodes.append(item_str)
            except (ValueError, SyntaxError):
                # If parsing fails, treat as raw node name
                log.debug("Could not parse node item as dict, treating as raw name: %s", item_str)
                target_nodes.append(item_str)

    target_nodes = [
        node for node in target_nodes if not (
            'storage' in node
            or 'serv' in node
            or 'crit' in node
        )
    ]
    
    log.info("Parsed target node names: %s", target_nodes)
    return target_nodes


def gather_host_config_pods() -> List[Dict[str, Any]]:
    rc, out, err = _run([
        "kubectl",
        "get",
        "pods",
        "--all-namespaces",
        "-l",
        "name=host-config",
        "-o",
        "json",
    ])
    if rc != 0:
        log.error("Failed to list host-config pods: %s", err or out)
        sys.exit(1)

    try:
        data = json.loads(out)
    except json.JSONDecodeError as exc:
        log.error("Could not parse kubectl JSON output: %s", exc)
        sys.exit(1)

    return data.get("items", [])


def build_cleanup_tasks(
    project_id: str, harness_ids: List[str], target_nodes: List[str]
) -> List[CleanupTask]:
    if not target_nodes:
        log.warning("No target nodes provided to build_cleanup_tasks")
        return []
    
    log.info("Building cleanup tasks for %d target nodes", len(target_nodes))
    
    pods = gather_host_config_pods()
    log.info("Found %d host-config pods", len(pods))

    # Create a set for faster lookup
    target_nodes_set = set(target_nodes)
    
    tasks: List[CleanupTask] = []
    pod_nodes_found = []
    
    for item in pods:
        spec = item.get("spec", {})
        metadata = item.get("metadata", {})
        node_name: Optional[str] = spec.get("nodeName")
        
        if not node_name:
            log.debug("Pod %s has no nodeName, skipping", metadata.get("name", "unknown"))
            continue
            
        node_name = node_name.strip()
        pod_nodes_found.append(node_name)
        
        if node_name not in target_nodes_set:
            log.debug("Pod %s on node %s not in target nodes, skipping", 
                     metadata.get("name", "unknown"), node_name)
            continue
            
        pod_name: str = metadata.get("name", "")
        namespace: str = metadata.get("namespace", "default")
        
        if not pod_name:
            log.warning("Pod has no name, skipping node %s", node_name)
            continue
            
        log.debug("Creating cleanup task for pod %s on node %s", pod_name, node_name)
        tasks.append(CleanupTask(pod_name, namespace, node_name, project_id, harness_ids))

    log.info("Pod nodes found: %s", sorted(set(pod_nodes_found)))
    log.info("Target nodes: %s", sorted(target_nodes))
    log.info("Created %d cleanup tasks", len(tasks))
    
    if not tasks:
        log.warning("No cleanup tasks created. Check if node names match between API and Kubernetes.")
        log.warning("Pod nodes: %s", pod_nodes_found[:10])  # Show first 10 for debugging
    
    # Prioritise nodes containing 'usr'
    tasks.sort(key=lambda t: ("usr" not in t.node_name, t.node_name))
    return tasks


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------

def main(argv: List[str] | None = None) -> None:  # noqa: D401
    parser = argparse.ArgumentParser(
        description="Delete stale shared data across cluster nodes.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--project-id",
        required=True,
        help="Project ID whose data should be removed.",
    )
    parser.add_argument(
        "harness_ids",
        nargs="+",
        help="One or more harness IDs to clean up.",
    )
    parser.add_argument(
        "--max-parallel",
        type=int,
        default=20,
        help="Maximum number of nodes to clean up in parallel.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging for troubleshooting.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be cleaned without actually doing it.",
    )
    args = parser.parse_args(argv)

    # ------------------------------------------------------------------
    # Input validation
    # ------------------------------------------------------------------
    def _validate(identifier: str, kind: str) -> None:
        if not identifier or not identifier.isalnum():
            parser.error(f"{kind} '{identifier}' must be non-empty and alphanumeric")

    _validate(args.project_id, "Project ID")
    for hid in args.harness_ids:
        _validate(hid, "Harness ID")

    agent_url = os.environ.get("PDT_AGENT_URL", 'http://localhost:8080')
    if not agent_url:
        parser.error("PDT_AGENT_URL environment variable is not set")

    # Set up logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
    )

    if args.dry_run:
        log.info("🔍 DRY RUN MODE - No actual cleanup will be performed")

    log.info("🚀 Starting cleanup for project_id=%s, harness_ids=%s", 
             args.project_id, args.harness_ids)
    log.info("Agent URL: %s", agent_url)

    try:
        log.info("Fetching target nodes from %s", agent_url)
        target_nodes = fetch_target_nodes(agent_url)
        if not target_nodes:
            log.warning("No nodes returned by agent – nothing to do.")
            return

        log.info("Discovered %d target nodes: %s", len(target_nodes), target_nodes)

        tasks = build_cleanup_tasks(args.project_id, args.harness_ids, target_nodes)
        if not tasks:
            log.warning("No host-config pods matched target nodes – exiting.")
            return

        if args.dry_run:
            log.info("🔍 DRY RUN: Would clean %d nodes", len(tasks))
            for task in tasks:
                log.info("🔍 Would clean node %s (pod %s in namespace %s)", 
                        task.node_name, task.pod_name, task.namespace)
            return

        log.info("Starting cleanup on %d nodes (max parallel=%d)…", len(tasks), args.max_parallel)

        success = 0
        with ThreadPoolExecutor(max_workers=args.max_parallel) as pool:
            fut_to_task = {pool.submit(task.run): task for task in tasks}
            for fut in as_completed(fut_to_task):
                task = fut_to_task[fut]
                try:
                    if fut.result():
                        success += 1
                except Exception as exc:  # pylint: disable=broad-except
                    log.error("💥 Unhandled exception cleaning %s: %s", task.node_name, exc)

        log.info("🏁 Finished cleanup – succeeded on %d/%d nodes", success, len(tasks))
        
        if success < len(tasks):
            log.warning("⚠️  Some cleanups failed. Check logs above for details.")
            sys.exit(1)
            
    except Exception as exc:  # pylint: disable=broad-except
        log.error("💥 Fatal error during cleanup: %s", exc)
        if args.debug:
            import traceback
            log.error("Traceback:\n%s", traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        sys.exit(130)