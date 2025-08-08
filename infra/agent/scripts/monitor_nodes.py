#!/usr/bin/env python3

import asyncio
import os
import time
import yaml
import logging
import json
import subprocess
from collections import defaultdict

from dataclasses import dataclass, field

import pydatatask
from pydatatask import repository as repomodule

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger(__name__)

BACKUP_BEFORE_DEADLINE = 20 * 60

K8S_BACKUP_INTERVAL = 30 * 60
PIPELINE_BACKUP_INTERVAL = 45 * 60

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

AGENT_STATE_DIR = "/pdt/agent-state"

NODE_STATE_PATH = "/pdt/agent-state/nodes.json"

def save_node_state(nodes):
    np = NODE_STATE_PATH + '.tmp'
    with open(np, "w") as f:
        json.dump(nodes, f)
    os.rename(np, NODE_STATE_PATH)

async def amain():
    log.warning("🔎📦  Starting node monitor")

    pipeline = pydatatask.get_current_directory_pipeline()
    async with pipeline:
        while True:
            try:
                await run(pipeline)
            except Exception as e:
                import traceback
                traceback.print_exc()
                log.error(f"🤡  Failed to run node monitor: {e}")

            await asyncio.sleep(10)

async def generate_node_list(pipeline: pydatatask.Pipeline):
    start_time = time.time()
    nodes = []
    pipeline.cache_flush()
    for task in pipeline.tasks.values():
        manager = task.manager
        from pydatatask.executor.container_manager import KubeContainerManager
        if isinstance(manager, KubeContainerManager):
            raw_nodes = await manager.cluster.get_nodes()
            for node in raw_nodes:
                node_name = node.metadata.name
                node_ip = node.status.addresses[0].address
                nodes.append({
                    'ip': node_ip,
                    'node_ip': node_ip,
                    'name': node_name
                })
            raw_pods = await manager.cluster.list_pods_by_label(f"name=host-config")
            for pod in raw_pods:
                pod_name = pod.metadata.name
                pod_ip = pod.status.pod_ip
                pod_node = pod.spec.node_name

                for node in nodes:
                    if node['name'] == pod_node:
                        node['ip'] = pod_ip
            break

    log.info(f"Noticed {len(nodes)} nodes")
    log.info(f"Nodes: {json.dumps(nodes)}")
    end_time = time.time()
    log.info(f"Generated {len(nodes)} nodes in {end_time - start_time} seconds")
    return nodes
            
async def run(pipeline: pydatatask.Pipeline):
    nodes = await generate_node_list(pipeline)
    save_node_state(dict(
        nodes=nodes,
        updated_at = int(time.time())
    ))



if __name__ == "__main__":
    log.warning("📦  Starting node monitor")
    asyncio.run(amain())
