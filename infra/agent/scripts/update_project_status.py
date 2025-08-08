#!/usr/bin/env python3

import asyncio
import os
import logging
import json

from collections import defaultdict
from pathlib import Path

from dataclasses import dataclass, field

import pydatatask
from shellphish_crs_utils.models.aixcc_api import StatusTasksState, StatusState

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger(__name__)

BACKUP_BEFORE_DEADLINE = 20 * 60

K8S_BACKUP_INTERVAL = 30 * 60
PIPELINE_BACKUP_INTERVAL = 45 * 60

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

STATUS_FILE = Path("/shared/status.json")
try:
    STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
except:
    pass

SUBMISSION_HISTORY_FILE = Path("/shared/submission_history.json")

async def update_tasks_status(pipeline: pydatatask.Pipeline):
    """"
    This function calculates the status of the tasks and submissions for a given pydatatask.Pipeline.
    THIS IS EXPENSIVE, DO NOT CALL IT TOO OFTEN.
    """

    pipeline.cache_flush()

    num_tasks_cancelled = 0
    num_tasks_errored = 0
    num_tasks_pending = 0
    num_tasks_processing = 0
    uploaded_tasks = []
    cancelled_tasks = []

    submission_attempt_keys = []
    submission_success_keys = []
    submission_failure_keys = []
    submission_waiting_keys = []

    try:
        # Get basic task information with retries and timeouts
        try:
            uploaded_tasks = (
                await pipeline.tasks["pipeline_input"].links["project_id"].repo.keys()
            )
        except Exception as e:
            log.warning("Error getting uploaded tasks: %s", e)
            uploaded_tasks = []

        cancelled_tasks = [] # nah
        #try:
        #    cancelled_tasks = (
        #        await pipeline.tasks["pipeline_input"].links["project_cancel"].repo.keys()
        #    )
        #except Exception as e:
        #    log.warning("Error getting cancelled tasks: %s", e)
        #    cancelled_tasks = []

        try:
            done_submitter_tasks = (
                await pipeline.tasks["submitter"].done.keys()
            )
        except Exception as e:
            log.warning("Error getting done submitter tasks: %s", e)
            done_submitter_tasks = []

        try:
            #canonical_build.canonical_build_artifacts
            live_submitter_tasks = (
                await pipeline.tasks['canonical_build'].links['canonical_build_artifacts'].repo.keys()
            )
            log.info("Completed canonical build tasks: %s", live_submitter_tasks)
        except Exception as e:
            log.warning("Error getting live canonical build tasks: %s", e)
            live_submitter_tasks = []

        #live_tasks_for_project = defaultdict(set)
        #for taskname, task in pipeline.tasks.items():
        #    live_keys = set()
        #    try:
        #        live_keys |= set(await task.ready.keys())
        #    except Exception as e:
        #        log.warning("Error getting ready keys: %s", e)

        #    try:
        #        live_keys |= set(await task.done.keys())
        #    except Exception as e:
        #        log.warning("Error getting done keys: %s", e)

        #    try:
        #        live_keys |= set(await task.links['live'].repo.keys())
        #    except Exception as e:
        #        log.warning("Error getting live keys: %s", e)

        #    for job_id in live_keys:
        #        try:
        #            if isinstance(task.input['project_id'], pydatatask.repomodule.RelatedItemRepository):
        #                project_id = await task.input['project_id'].lookup()
        #            else:
        #                project_id = job_id
        #        except Exception as e:
        #            log.warning("Error getting project id: %s", e)
        #        live_tasks_for_project[project_id].add(taskname)

        # Calculate errored tasks
        unrecoverably_errored_tasks = set() # nah
        #for project_id, live_jobs in live_tasks_for_project.items():
        #    if 'submitter' not in live_jobs and project_id in done_submitter_tasks and project_id not in cancelled_tasks:
        #        unrecoverably_errored_tasks.add(project_id)
        #    elif live_jobs.issubset({'coverage_trace', 'submitter'}):
        #        unrecoverably_errored_tasks.add(project_id)

        # Calculate pending tasks
        pending_tasks = set(uploaded_tasks)
        pending_tasks.difference_update(set(live_submitter_tasks))
        pending_tasks.difference_update(set(cancelled_tasks))
        pending_tasks.difference_update(set(done_submitter_tasks))

        # Update task counts
        num_tasks_cancelled = len(cancelled_tasks)
        num_tasks_processing = len(live_submitter_tasks)
        num_tasks_pending = len(pending_tasks)
        num_tasks_errored = len(unrecoverably_errored_tasks)

        # Get submission information with retries and timeouts
        try:
            submission_attempt_keys = await pipeline.tasks['submitter'].links['submissions'].repo.keys()
            log.info("Submission attempt keys: %s", submission_attempt_keys)
        except Exception as e:
            log.warning("Error getting submission attempt keys: %s", e)
            submission_attempt_keys = []

        try:
            submission_success_keys = await pipeline.tasks['submitter'].links['submission_results_success'].repo.keys()
            log.info("Submission success keys: %s", submission_success_keys)
        except Exception as e:
            log.warning("Error getting submission success keys: %s", e)
            submission_success_keys = []
        
        try:
            submission_failure_keys = await pipeline.tasks['submitter'].links['submission_results_failed'].repo.keys()
            log.info("Submission failure keys: %s", submission_failure_keys)
        except Exception as e:
            log.warning("Error getting submission failure keys: %s", e)
            submission_failure_keys = []

        # Calculate this only with live information rather than historic
        # So that when the task is deleted the waiting ones go away
        num_submission_waiting_keys = len(submission_attempt_keys) - len(submission_success_keys) - len(submission_failure_keys)

        try:
            if SUBMISSION_HISTORY_FILE.exists():
                submission_history = json.loads(SUBMISSION_HISTORY_FILE.read_text())
            else:
                submission_history = defaultdict(list)
        except Exception as e:
            import traceback
            traceback.print_exc()
            log.warning("Error getting submission history: %s", e)
            submission_history = defaultdict(list)
        
        submission_success_keys = set(submission_success_keys)
        submission_success_keys.update(set(submission_history.get('success', [])))

        submission_failure_keys = set(submission_failure_keys)
        submission_failure_keys.update(set(submission_history.get('failed', [])))

        try:
            submission_history['success'] = list(submission_success_keys)
            submission_history['failed'] = list(submission_failure_keys)
            SUBMISSION_HISTORY_FILE.write_text(json.dumps(submission_history, indent=2))
        except Exception as e:
            import traceback
            traceback.print_exc()
            log.warning("Error writing submission history: %s", e)


    except (TimeoutError, Exception) as e:
        log.error("Error in get_tasks_status", exc_info=True)
        # Return default values if overall timeout is reached
        status_state = StatusTasksState(
            canceled=0,
            errored=0,
            pending=0,
            processing=0,
            failed=0,
            succeeded=0,
            waiting=0
        )
    


    status_state = StatusTasksState(
        # task stats
        canceled=num_tasks_cancelled,
        errored=num_tasks_errored,
        pending=num_tasks_pending,
        processing=num_tasks_processing,

        # submission stats
        failed=len(submission_failure_keys),
        succeeded=len(submission_success_keys),
        waiting=num_submission_waiting_keys,
    )

    log.info("Updating status file with %s", status_state)

    STATUS_FILE.write_text(status_state.model_dump_json(indent=2))


async def amain():
    log.warning("📊 Starting status by project")

    pipeline = pydatatask.get_current_directory_pipeline()
    async with pipeline:
        while True:
            try:
                await update_tasks_status(pipeline)
            except:
                pass
            await asyncio.sleep(5*60)

if __name__ == "__main__":
    asyncio.run(amain())
