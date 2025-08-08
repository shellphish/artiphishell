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


@dataclass
class ProjectStatus:
    jobs: list[tuple[str, str]] = field(default_factory=list)
    halted: bool = False
    deadline: int = -1
    type: str = "full"
    cancelled: bool = False
    cleanup_launched: bool = False


@dataclass
class JobStatus:
    project_id: str
    ready: bool
    done: bool


PROJECT_STATUS: dict[str, ProjectStatus] = {}
JOB_STATUS: dict[tuple[str, str], JobStatus] = {}


# Keep references to background cleanup tasks so they are not garbage
# collected and so that exceptions are surfaced.
POST_CLEANUP_TASKS: set[asyncio.Task] = set()

def start_backup_pipeline(name):
    try:
        log.warning(f"📦  Backup for {name} is starting...")
        backup_lock_file = f"/tmp/.backup_in_progress_{name}"
        with open(backup_lock_file, "w") as f:
            f.write(f"{time.time()}")
        # Store the process handle to prevent zombies
        backup_process = subprocess.Popen(
            f'{SCRIPT_DIR}/local_backup_during_game.sh {backup_lock_file} >> /tmp/backup.log 2>&1',
            shell=True,
            start_new_session=True
        )
        # Ensure the process is properly detached
        backup_process.poll()
    except Exception as e:
        log.error(f"🤡  Failed to start backup for {name}: {e}")
        return False
    return True

ACTIVE_TASKS_PATH = "/pdt/active_tasks.json"

def save_active_projects_for_llm(tasks):
    with open(ACTIVE_TASKS_PATH+'.tmp', "w") as f:
        json.dump(tasks, f)
    os.rename(ACTIVE_TASKS_PATH+'.tmp', ACTIVE_TASKS_PATH)

def get_repo_name(pipeline: pydatatask.Pipeline,node: repomodule.Repository):
    for task, repo, data in pipeline.graph.in_edges(node, data=True):
        return f"{task.name}.{data['link_name']}"
        
    # Get outgoing edges (Repository -> Task) 
    for repo, task, data in pipeline.graph.out_edges(node, data=True):
        return f"{task.name}.{data['link_name']}"

    return None


async def destroy_task_data(pipeline: pydatatask.Pipeline, task_id: str, dry_run=True):
    log.warning(f"💣💣💣💣  Destroying task data for {task_id} 💣💣💣💣")
    # WE ARE GOING TO DESTROY ALL DATA RELATED TO THIS TASK
    # We will do this in 2 steps:
    # 1. Iterate all metadata repos and locate any ids which include this given task_id as a project marker
    # 2. Now delete any entries in any repo that match any of these ids
    name_to_repo = {}
    ids_to_nuke = set([task_id])
    repos_with_no_matches = []

    async def check_repo_for_project_matches(node: repomodule.Repository):
        found_some = False
        has_any = False
        example = None
        all_metadata = await node.info_all()
        # Iterate through each metadata entry
        for job_id, metadata in all_metadata.items():
            has_any = True
            if job_id in ids_to_nuke:
                found_some = True
                continue

            is_a_match = False

            if metadata.get("project_id") == task_id:
                is_a_match = True
            elif metadata.get("pdt_project_id") == task_id:
                is_a_match = True

            if is_a_match:
                #print(f"  Job ID: {repr_name}:{job_id} is a match for {task_id}")
                ids_to_nuke.add(job_id)
                found_some = True
                continue

            example = (job_id, metadata)


        if has_any and not found_some:
            return False

        return True

    for node in pipeline.graph:
        if not isinstance(node, repomodule.Repository):
            continue
        # Get all edges connected to this repository
        names = set()

        
        # Get incoming edges (Repository <- Task)
        for task, repo, data in pipeline.graph.in_edges(node, data=True):
            names.add(f"{task.name}.{data['link_name']}")
            
        # Get outgoing edges (Repository -> Task) 
        for repo, task, data in pipeline.graph.out_edges(node, data=True):
            names.add(f"{task.name}.{data['link_name']}")

        for name in names:
            name_to_repo[name] = node

        if not isinstance(node, repomodule.MetadataRepository):
            continue

        repr_name = next(iter(names),None)
        
        #print(f"Repository {node} is referenced as: {names}")
        
        # Get all metadata from this repository as a dict
        #print(f"Metadata in {names}: {len(all_metadata)} entries")
        

        if repr_name and '.done' in repr_name:
            continue
        if repr_name and '.success' in repr_name:
            continue

        if not await check_repo_for_project_matches(node):
            repos_with_no_matches.append(repr_name)

    extra_visited = set()

    # Now we check to see if there are any task repos we missed...
    for task in pipeline.tasks.values():
        for name,link in task.links.items():
            repo_name = f"{task.name}.{name}"

            if '.done' in name or '.success' in name:
                continue

            if repo_name in name_to_repo:
                continue

            if repo_name in extra_visited:
                continue

            repo = link.repo
            if not isinstance(repo, repomodule.MetadataRepository):
                continue

            if not await check_repo_for_project_matches(repo):
                repos_with_no_matches.append(repo_name)

            extra_visited.add(repo_name)


    if repos_with_no_matches:
        print(f"⚠️ Populated Metadata Repos which did not match {task_id}: {repos_with_no_matches}")

    if ids_to_nuke:
        print(f"🔥 # IDs to nuke: {len(ids_to_nuke)}")


    # First we delete the crs_task so that we don't accidentally restart any tasks

    crs_task_input_repo = name_to_repo.get('pipeline_input.crs_task')
    if crs_task_input_repo:
        for key in await crs_task_input_repo.keys():
            if key in ids_to_nuke:
                print(f"💣  Deleting {crs_task_input_repo}:{key}")
                if not dry_run:
                    await crs_task_input_repo.delete(key)
    sarif_repo = name_to_repo.get('pipeline_input.sarif_metadata/')
    if sarif_repo:
        for key in await sarif_repo.keys():
            if key in ids_to_nuke:
                print(f"💣  Deleting {sarif_repo}:{key}")
                if not dry_run:
                    await sarif_repo.delete(key)

    # Ok now iterate all repos and delete all entries which match any of the ids_to_nuke

    repos_with_no_matches = []

    async def nuke_repo(node: repomodule.Repository):
        # We want to iterate over keys (NOT VALUES)
        found_any = False
        has_any = False
        num_deleted = 0
        for key in await node.keys():
            has_any = True
            if key in ids_to_nuke:
                num_deleted += 1
                found_any = True
                if not dry_run:
                    await node.delete(key)
            
        return num_deleted, not (has_any and not found_any)

    for node in pipeline.graph:
        if not isinstance(node, repomodule.Repository):
            continue

        repo_name = get_repo_name(pipeline,node)

        num_deleted, all_good = await nuke_repo(node)

        if num_deleted > 0:
            print(f"💣  Deleted {num_deleted} entries from {repo_name}")

        if not all_good:
            repos_with_no_matches.append(repo_name)

    extra_visited = set()

    for task in pipeline.tasks.values():
        for name,link in task.links.items():
            repo_name = f"{task.name}.{name}"

            if repo_name in name_to_repo:
                continue

            if repo_name in extra_visited:
                continue

            num_deleted, all_good = await nuke_repo(link.repo)

            if num_deleted > 0:
                print(f"💣  Deleted {num_deleted} entries from {repo_name}")

            if not all_good:
                repos_with_no_matches.append(repo_name)

            extra_visited.add(repo_name)

    if repos_with_no_matches:
        print(f"⚠️ Populated Repos with did not match project {task_id}: {repos_with_no_matches}")
        


async def amain():
    log.warning("🔎  Starting monitor by project")
    log.warning("📦  Backup interval: %d min", K8S_BACKUP_INTERVAL / 60)
    log.warning("🎱  K8S metadata backup interval: %d min", K8S_BACKUP_INTERVAL / 60)

    last_k8s_backup_time = 0
    last_pipeline_backup_time = time.time()
    pipeline = pydatatask.get_current_directory_pipeline()
    async with pipeline:

        while True:
            try:
                await run(pipeline)
            except Exception as e:
                import traceback
                traceback.print_exc()
                log.error(f"🤡  Failed to run monitor by project: {e}")

            await asyncio.sleep(10)
            #try:
            #    if time.time() - last_k8s_backup_time > K8S_BACKUP_INTERVAL:
            #        last_k8s_backup_time = time.time()
            #        log.warning("🎱 Backing up k8s metadata...")
            #        # Store the process handle to prevent zombies
            #        k8s_backup_process = subprocess.Popen(
            #            f'{SCRIPT_DIR}/backup_k8s_info.sh > /tmp/backup_k8s_info.log 2>&1',
            #            shell=True,
            #            start_new_session=True
            #        )
            #        # Ensure the process is properly detached
            #        k8s_backup_process.poll()
            #except Exception as e:
            #    import traceback
            #    traceback.print_exc()
            try:
                diff = time.time() - last_pipeline_backup_time
                log.warning("⌚  Pipeline will backup in %d min", (PIPELINE_BACKUP_INTERVAL - diff) // 60)
                if diff > PIPELINE_BACKUP_INTERVAL:
                    last_pipeline_backup_time = time.time()
                    start_backup_pipeline("periodic")
            except Exception as e:
                log.error(f"🤡  Failed to start pipeline backup: {e}")

async def run(pipeline: pydatatask.Pipeline):
    project_list = (
        await pipeline.tasks["pipeline_input"].links["project_id"].repo.keys()
    )
    crs_tasks = pipeline.tasks["pipeline_input"].links["crs_task"].repo
    if len(project_list) == 0:
        log.warning("🫥  No projects yet")

    active_tasks = []

    for project_id in project_list:
        if project_id not in PROJECT_STATUS:
            blob = await crs_tasks.blob.blobinfo(project_id)
            metadata = yaml.safe_load(blob)
            deadline = metadata["deadline"]
            task_type = metadata["type"]
            PROJECT_STATUS[project_id] = ProjectStatus(deadline=deadline, type=task_type)

            os.environ["JOB_ID"] = project_id
            log.warning(f"🌄  Starting project {project_id}")
            active_tasks.append({
                "project_id": project_id,
                "type": task_type,
            })
        elif PROJECT_STATUS[project_id].cancelled:
            continue


        else:
            deadline = PROJECT_STATUS[project_id].deadline
            current_time = int(time.time() * 1000)
            try:
                diff = (deadline - current_time) // 1000 // 60
                log.warning("🕒  Project %s: %d min left", project_id, diff)

                backup_timeframe = deadline - BACKUP_BEFORE_DEADLINE * 1000
                backup_lock_file = f"/tmp/.backup_in_progress_{project_id}"
                if (
                    deadline != -1
                    and current_time > backup_timeframe
                    and not os.path.exists(backup_lock_file)
                ):
                    log.warning('⌛  Project %s almost up, taking backup...', project_id)
                    start_backup_pipeline(project_id)

            except Exception as e:
                import traceback
                traceback.print_exc()

            EARLY_CANCEL_TIME = 5 * 60 * 1000

            if deadline != -1 and current_time > deadline - EARLY_CANCEL_TIME:
                PROJECT_STATUS[project_id].halted = True
                log.warning(f"☠️ Deadline exceeded for project {project_id}")
                cancel_repo = (
                    pipeline.tasks["pipeline_input"].links["project_cancel"].repo
                )
                await cancel_repo.dump(project_id, "")

                # Optionally launch the pod cleanup script unless log
                # collection on cancel is enabled.  Ensure we only launch it
                # once per project.
                collect_logs_on_cancel = (
                    os.environ.get("ARTIPHISHELL_GLOBAL_ENV_COLLECT_LOGS_ON_CANCEL", "false").lower() == "true"
                )

                if not collect_logs_on_cancel and not PROJECT_STATUS[project_id].cleanup_launched:
                    try:
                        os.system("rm -rf /pdt/agent-state/nginx_cache/ || true")
                    except Exception as e:
                        log.error("🤡  Failed to remove nginx cache: %s", e)

                    try:
                        current_time = int(time.time() * 1000)
                        # ONLY DO THIS IF WE ARE BEFORE DEADLINE
                        if current_time < deadline - EARLY_CANCEL_TIME:
                            # Give the system a brief moment to register the cancel
                            await asyncio.sleep(2)
                            subprocess.Popen(
                                ["python3", os.path.join(SCRIPT_DIR, "pre_delete_pods_for_cancel.py")],
                                stderr=subprocess.STDOUT,
                                start_new_session=True,
                            )
                            PROJECT_STATUS[project_id].cleanup_launched = True
                            log.warning(
                                "🚮  Launched pre_delete_pods_for_cancel.py for early pod cleanup (collect_logs_on_cancel=%s)",
                                collect_logs_on_cancel,
                            )
                    except Exception as e:
                        log.error("🤡  Failed to start pre-delete pod cleanup script: %s", e)


                # Check if the leader has acknowledged that the project is done
                cancel_complete_file = f"/pdt/cancel_complete_{project_id}.info"
                if os.path.exists(cancel_complete_file):
                    try:
                        cleanup_task = asyncio.create_task(post_cancel_cleanup(pipeline, project_id))
                        POST_CLEANUP_TASKS.add(cleanup_task)
                        cleanup_task.add_done_callback(POST_CLEANUP_TASKS.discard)
                    except Exception as e:
                        log.error(f"🤡  Failed to post-cancel cleanup for {project_id}: {e}")

                    PROJECT_STATUS[project_id].cancelled = True

                os.environ["JOB_ID"] = project_id
            else:
                # Project is still active, add it to the active tasks
                active_tasks.append({
                    "project_id": project_id,
                    "type": PROJECT_STATUS[project_id].type,
                })

    save_active_projects_for_llm(active_tasks)

    for taskname, task in pipeline.tasks.items():
        finished_jobs = set(await task.done.keys())
        ready_jobs = set(await task.ready.keys())

        for job_id in ready_jobs | finished_jobs:
            try:
                if (taskname, job_id) not in JOB_STATUS:
                    env, _, _ = await task.build_template_env_cached(job_id, 0)
                    project_id = env["project_id"]
                    assert isinstance(project_id, str)
                    job_status = JobStatus(
                        project_id, job_id in ready_jobs, job_id in finished_jobs
                    )
                    JOB_STATUS[(taskname, job_id)] = job_status
                    PROJECT_STATUS[project_id].jobs.append((taskname, job_id))
            except Exception as e:
                pass


# -----------------------------------------------------------------------------
# Post-cancel cleanup helper
# -----------------------------------------------------------------------------


async def post_cancel_cleanup(pipeline: pydatatask.Pipeline, project_id: str) -> None:
    """Perform final backup, data destruction and shared-directory cleanup.
    """
    # ------------------------------------------------------------------
    # 1. Final tiny backup – awaited
    # ------------------------------------------------------------------
    try:
        log.warning("📦  Taking final backup for %s", project_id)
        proc = await asyncio.create_subprocess_shell(
            f"{SCRIPT_DIR}/final_project_backup.sh /tmp/.tiny_backup_{project_id}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=4 * 60)
            if proc.returncode == 0:
                log.info("✅  Final backup for %s completed", project_id)
            else:
                log.error(
                    "🤡  Final backup script exited with %d for %s – %s",
                    proc.returncode,
                    project_id,
                    stderr.decode() if stderr else "<no stderr>",
                )
        except asyncio.TimeoutError:
            proc.kill()
            log.error("🤡  Final backup for %s timed out", project_id)
    except Exception as e:  # pylint: disable=broad-except
        log.error("🤡  Failed to start/await final backup for %s: %s", project_id, e)

    # ------------------------------------------------------------------
    # 2. Determine harness IDs involved in the project
    # ------------------------------------------------------------------
    harness_ids: list[str] = []
    try:
        repo = pipeline.tasks["harness_info_splitter"].links["target_split_metadata_path"].repo
        metadata = await repo.info(project_id)
        harness_ids = [k for k, _ in metadata.get("harness_infos", {}).items()]
        log.warning("🪢  Found %d harness ids for %s: %s", len(harness_ids), project_id, harness_ids)
    except Exception as e:  # pylint: disable=broad-except
        import traceback
        traceback.print_exc()
        log.error("🤡  Failed to get harness ids for %s: %s", project_id, e)

    # ------------------------------------------------------------------
    # 3. Optionally destroy task data & restart services (blocking)
    # ------------------------------------------------------------------
    try:
        if os.environ.get("ARTIPHISHELL_GLOBAL_ENV_DELETE_ON_CANCEL", os.environ.get("PDT_DELETE_ON_CANCEL")) == "true":
            await destroy_task_data(pipeline, project_id, dry_run=False)
            time.sleep(5)
            log.warning("💣💣💣💣  Restarting pydatatask.cli.main for %s 💣💣💣💣", project_id)
            subprocess.check_call(["pkill", "-f", "pydatatask.cli.main"])  # noqa: S603
            try:
                log.warning("🧹  Wiping analysis graph data for %s", project_id)
                proc = await asyncio.create_subprocess_exec(
                    "ag-wipe-project-id-nodes",
                    project_id,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await proc.communicate()
                if proc.returncode != 0:
                    log.error(
                        "🤡  ag-wipe-project-id-nodes exited with %d for %s – %s",
                        proc.returncode,
                        project_id,
                        stderr.decode() if stderr else "<no stderr>",
                    )
            except Exception as e:
                log.error("🤡  Failed to wipe analysis graph data for %s: %s", project_id, e)
            await asyncio.sleep(10)
            try:
                log.warning("🔄  Restarting services for %s", project_id)
                proc = await asyncio.create_subprocess_shell(
                    f"{SCRIPT_DIR}/restart_services.sh {project_id}",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                try:
                    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=4 * 60)
                    if proc.returncode != 0:
                        log.error(
                            "🤡  Restart services script exited with %d for %s – %s",
                            proc.returncode,
                            project_id,
                            stderr.decode() if stderr else "<no stderr>",
                        )
                except asyncio.TimeoutError:
                    proc.kill()
                    log.error("🤡  Restart services for %s timed out", project_id)
            except Exception as e:
                log.error("🤡  Failed to restart services for %s: %s", project_id, e)
    except Exception as e:  # pylint: disable=broad-except
        log.error("🤡  Failed to restart services for %s: %s", project_id, e)

    if os.environ.get("ARTIPHISHELL_GLOBAL_ENV_DELETE_ON_CANCEL", os.environ.get("PDT_DELETE_ON_CANCEL")) == "true":
        # ------------------------------------------------------------------
        # 4. Launch shared-data cleanup (fire-and-forget)
        # ------------------------------------------------------------------
        try:
            cleanup_script = os.path.join(SCRIPT_DIR, "delete_shared_data_from_nodes.py")
            cmd = [
                "python3",
                cleanup_script,
                "--project-id",
                project_id,
            ] + (harness_ids or [])

            subprocess.Popen(  # noqa: S603
                cmd,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            log.warning(
                "🧹  Launched delete_shared_data_from_nodes.py for project %s (harness_ids=%s)",
                project_id,
                harness_ids,
            )
        except Exception as e:  # pylint: disable=broad-except
            log.error("🤡  Failed to launch shared data cleanup script for %s: %s", project_id, e)

if __name__ == "__main__":
    log.warning("Starting Monitor by Project")
    log.warning("INFLUXDB_URL: %s", os.getenv("INFLUXDB_URL"))
    log.info("INFLUXDB_TOKEN: %s", os.getenv("INFLUXDB_TOKEN"))
    log.info("INFLUXDB_BUCKET: %s", os.getenv("INFLUXDB_BUCKET"))
    log.info("INFLUXDB_ORG: %s", os.getenv("INFLUXDB_ORG"))
    asyncio.run(amain())
