#!/usr/bin/env python3

"""
This script works by listing all oss_fuzz_project_builds, and uses an alg to decide which artifacts can be pruned.

- If the artifact is younger than 1 hour, it is not pruned
- If the artifact has more than 1 hit it is not pruned

The script iterates over all the patch metadata, and any `build_request_id`s are excluded from the pruning.

For all pruned artifacts, we delete them from the nginx cache.

Then we do a stronger check to determine if the artifact can be deleted from the entire pipeline.

This check requires:
- The artifact is over 2 hours old
- The artifact's patch_request metadata must include a patch file

"""

import asyncio
import os
import time
import yaml
import logging
import json
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict

from dataclasses import dataclass, field
from pathlib import Path

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
NGINX_CACHE_PATH = Path("/pdt/agent-state/nginx_cache")

def save_node_state(nodes):
    np = NODE_STATE_PATH + '.tmp'
    with open(np, "w") as f:
        json.dump(nodes, f)
    os.rename(np, NODE_STATE_PATH)

async def amain():
    log.warning("📦🔫  Starting oss_fuzz_project_build cache pruning")

    pipeline = pydatatask.get_current_directory_pipeline()
    async with pipeline:
        while True:
            try:
                await run(pipeline)
            except Exception as e:
                import traceback
                traceback.print_exc()
                log.error(f"🤡  Failed to prune oss_fuzz_project_builds: {e}")

            await asyncio.sleep(10)

def get_provider_info():
    state_dir = Path(AGENT_STATE_DIR)
    state_file = state_dir / 'provider_urls.yaml'
    if not state_file.exists():
        return {}

    # TODO check to see if file was actually updated?
    try:
        current_data = yaml.safe_load(state_file.read_text())
    except Exception as e:
        import traceback
        traceback.print_exc()
        return None
    return current_data


async def run(pipeline: pydatatask.Pipeline):
    log.info("🔎 Checking all oss_fuzz_project_builds")
    pipeline.cache_flush()

    allow_patch_task = pipeline.tasks['allow_patch_submission']
    patch_metadata = await allow_patch_task.links['patch_metadata'].repo.info_all()

    # Filter out messed up patch metadata we can never act on
    patch_metadata = {
        k:v for k,v in patch_metadata.items()
        if (
            v.get('pdt_project_id')
            and v.get('poi_report_id')
        )
    }

    BUILD_KEY = 'build_request_id'

    builds_associated_with_patches = {
        patch_meta[BUILD_KEY]: patch_meta
        for patch_id, patch_meta in patch_metadata.items()
        if (
            BUILD_KEY in patch_meta
            and patch_meta[BUILD_KEY] 
        )
    }

    log.info(f"🔎🩹 Found {len(builds_associated_with_patches)} builds associated with patches / {len(patch_metadata)} patches")

    if len(builds_associated_with_patches) != len(patch_metadata):
        log.warning(f"Some patches are missing , it is not safe to prune!!")
        return

    provider_info = get_provider_info()

    build_task = pipeline.tasks['oss_fuzz_project_build']
    build_repo = build_task.links['build_request'].repo
    build_artifacts_repo = build_task.links['project_build_artifacts'].repo
    build_stdout_repo = build_task.links['project_build_log_stdout'].repo
    build_stderr_repo = build_task.links['project_build_log_stderr'].repo
    build_metadata_repo = build_task.links['project_build_metadata'].repo
    build_info = await build_repo.info_all()

    for build_id, build_info in build_info.items():
        has_patch = 'patch' in build_info and build_info['patch'] is not None

        if not await build_artifacts_repo.contains(build_id):
            log.info(f"⏭️  Build {build_id} has no artifacts, skipping")
            continue
        
        if not has_patch:
            log.info(f"⏭️  Build {build_id} has no patch, skipping")
            continue

        if build_id in builds_associated_with_patches:
            log.info(f"⏭️  Build {build_id} is associated with a patch, skipping")
            continue

        done_info = await build_task.links['done'].repo.info(build_id)
        if not done_info:
            log.warning(f"Build {build_id} is not in the done repo (probably still building), skipping")
            continue

        age = datetime.now(done_info['end_time'].tzinfo) - done_info['end_time']

        if age < timedelta(hours=1):
            continue

        provider_key = f'project_build_artifacts/{build_id}'

        if provider_key not in provider_info:
            log.warning(f"🔎 Build {build_id} is not in the provider info, no usage information, skipping")
            continue

        entry = provider_info[provider_key]

        if entry.get('hit_count', 0) > 1:
            log.info(f"⏭️  Build {build_id} has more than 1 hit, skipping")
            continue

        RECENTLY_USED_THRESHOLD = 60 * 60
        
        if time.time() - entry.get('last_used', 0) < RECENTLY_USED_THRESHOLD:
            log.info(f"⏭️  Build {build_id} was recently used, skipping")
            continue

        # We are now good to prune from nginx cache

        nginx_cache_file = NGINX_CACHE_PATH / f"project_build_artifacts.{build_id}"

        if nginx_cache_file.exists():
            log.info(f"🗡️ Pruning {nginx_cache_file} with age {age}")
            os.unlink(nginx_cache_file)

        if age < timedelta(hours=2):
            continue

        log.info(f"🔎 Build {build_id} ended {age} ago")

        # We are now good to prune from the pipeline
        # It is over 2 hours old
        # It has a patch
        # It has no hits (besides the original one)
        # It was not requested recently
        # It is not associated with a patch

        log.info(f"💀 Pruning build {build_id} from the pipeline")
        await build_artifacts_repo.delete(build_id)

        # TODO(finaldeploy): Disable this 
        keep_failed_logs = False

        keep_logs = False 
        if not done_info.get('success', False):
            keep_logs = True

        build_metadata = await build_metadata_repo.info(build_id)
        if build_metadata and not build_metadata.get('build_success', False):
            keep_logs = True

        if keep_logs and keep_failed_logs:
            log.info(f"🪵 Keeping logs for failed build {build_id}")
        else:
            await build_repo.delete(build_id)
            await build_stdout_repo.delete(build_id)
            await build_stderr_repo.delete(build_id)
        
if __name__ == "__main__":
    asyncio.run(amain())
