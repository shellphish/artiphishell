import pydatatask
import logging
import time
from collections import defaultdict
from typing import Any

async def harnesses(pipeline: pydatatask.Pipeline, task: str, job: str, replica: int) -> float:
    # FIXME DO SOMETHING COOL!
    return 0.0

log = logging.getLogger(__name__)

from functools import lru_cache
from async_lru import alru_cache

QUEUE_TTL_SECONDS = 60*10

class HashablePipelineSingleton:
    """
    This class is used to allow us to pass the pipeline to lru_cache
    without it being used as a cache key.
    This class will always match with other HashablePipelineSingleton objects,
    meaning that when used as a cache key, it doesn't matter what the pipeline is.
    In addition we also drop the actual pipeline reference after we use it
    which will prevent the pipeline reference from staying in the cache
    """
    def __init__(self, pipeline: pydatatask.Pipeline):
        self.pipeline = pipeline
    
    def __hash__(self):
        # The pipeline should not be a cache key, but we need to hash it to use lru_cache
        return 1  

    def __eq__(self, other):
        # two ConstantHash objects are always equal
        return isinstance(other, HashablePipelineSingleton)

    def drop(self):
        # So we avoid keeping a reference to the pipeline in the cache
        self.pipeline = None

def repo_related(task: pydatatask.Task, repo: str) -> Any:
    try:
        return task._repo_related(repo)
    except Exception as e:
        return None

async def get_harness_info_directly(task: pydatatask.Task, job: str) -> str|None:
    harness_info_repo = repo_related(task, 'harness_info')
    if harness_info_repo is None:
        return None
    harness_info = await harness_info_repo.info(job)
    return harness_info.get('harness_info_id')

async def get_harness_info_via_crashing_input_metadata(task: pydatatask.Task, job: str) -> str|None:
    crashing_input_metadata_repo = repo_related(task,'crashing_input_metadata')
    if crashing_input_metadata_repo is None:
        crashing_input_metadata_repo = repo_related(task,'dedup_pov_report_representative_metadatas')
    if crashing_input_metadata_repo is None:
        return None
    crashing_input_metadata = await crashing_input_metadata_repo.info(job)
    return crashing_input_metadata.get('harness_info_id')

async def get_harness_info_via_pov_report(task: pydatatask.Task, job: str) -> str|None:
    pov_report_repo = repo_related(task, 'pov_guy_report_meta')
    if pov_report_repo is None:
        return None

    pov_report = await pov_report_repo.info(job)
    return pov_report.get('harness_info_id')

async def get_harness_info_via_poi_report(task: pydatatask.Task, job: str) -> str|None:
    pov_report_repo = repo_related(task, 'poi_report_meta')
    if pov_report_repo is None:
        pov_report_repo = repo_related(task, 'point_of_interest_meta')
    if pov_report_repo is None:
        pov_report_repo = repo_related(task, 'point_of_interest')
    if pov_report_repo is None:
        return None

    try:
        pov_report = await pov_report_repo.info(job)
    except Exception as e:
        log.warning(f"[priorities.get_harness_info_via_poi_report] Error fetching poi_report for job {job} in task {task}: {e}")
        raise
    return pov_report.get('harness_info_id')

@alru_cache(maxsize=10000)
async def lookup_harness_info_id(pipeline: HashablePipelineSingleton, task: str, job: str) -> str:
    task_obj = pipeline.pipeline.tasks[task]
    if task in ['povguy', 'povguy_losan', 'povguy_delta', 'crash_exploration']:
        res = await get_harness_info_via_crashing_input_metadata(task_obj, job)
    elif task in ['poiguy']:
        res = await get_harness_info_via_pov_report(task_obj, job)
    elif task in {
        'patcherq',
        'kumushi', 'kumushi_delta',
        'kumushi_heavy','kumushi_delta_heavy',
        'patchery', 'patchery_heavy_mode',
        'dyva_agent',
    }:
        res = await get_harness_info_via_poi_report(task_obj, job)
    else:
        res = await get_harness_info_directly(task_obj, job)
        if res is None:
            res = await get_harness_info_via_pov_report(task_obj, job)
        if res is None:
            res = await get_harness_info_via_crashing_input_metadata(task_obj, job)

    #log.info(f"lookup_harness_info_id for {task} {job} -> {res}")

    # TODO also fetch the time of the input so we can sort by that
    return res

async def is_task_running(pipeline: pydatatask.Pipeline, task: str, job: str) -> bool:
    """Check if a task is currently running (live) for a specific job.
    Returns True if the task is running, False if it's queued or not ready."""
    task_obj = pipeline.tasks[task]
    live_repo = repo_related(task_obj, 'live')
    return await live_repo.contains(job)

async def is_task_done(pipeline: pydatatask.Pipeline, task: str, job: str) -> bool:
    task_obj = pipeline.tasks[task]
    return await task_obj.done.contains(job)

MAX_QUEUE_SIZE = 100

# This is cached such that we only update it every QUEUE_TTL_SECONDS
@alru_cache(maxsize=20, ttl=QUEUE_TTL_SECONDS)
async def load_all_harness_queues_for_task(pipeline: HashablePipelineSingleton, task: str) -> tuple[dict[str, int], dict[str, int]]:
    """
    Group all jobs for a task by their harness_info_id.
    
    Args:
        pipeline: The pipeline singleton wrapper
        task: The name of the task to analyze
        
    Returns:
        A tuple of (prio_cache, queue_counts)
        prio_cache is a dictionary mapping from job_id to a priority
        queue_counts is a dictionary mapping from harness_info_id to a count of jobs in the queue
    """
    # Get the task object
    start_time = time.time()
    task_obj = pipeline.pipeline.tasks[task]
    
    queue_counts = defaultdict(int)

    prio_cache = {}

    # This is unsorted as we don't have a good sort key right now
    # If you want to sort, best to pre-sort the jobs before they are iterated here...
    #    The real hack would be to use a lex sort on the job_id and make the job_id start with time

    # Process each job
    async for job_id in task_obj.ready:
        # Get the harness_info_id for this job
        # TODO can this async alru cache look be made faster by having a non-async cache as well?
        harness_info_id = await lookup_harness_info_id(pipeline, task, job_id) or "unknown"

        # TODO is there a better way to do this than looking up the harness_info every time?
        v = queue_counts[harness_info_id]
        if v > MAX_QUEUE_SIZE:
            continue

        prio_cache[job_id] = v
        queue_counts[harness_info_id] = v + 1

    log.info(f"harness_queues for {task}: { {k:v for k,v in queue_counts.items()} }")

    end_time = time.time()
    log.info(f"load_all_harness_queues_for_task for {task} took {end_time - start_time} seconds")
    
    return (prio_cache, queue_counts)


@alru_cache(maxsize=10000, ttl=QUEUE_TTL_SECONDS)
async def get_index_of_task_in_harness_queue(
    pipeline: HashablePipelineSingleton,
    task: str,
    job: str,
) -> int|None:
    job_prios, queue_counts = await load_all_harness_queues_for_task(
        pipeline,
        task,
    )

    prio = job_prios.get(job)
    if not (prio is None):
        return prio
    
    harness_info_id = await lookup_harness_info_id(pipeline, task, job)
    if harness_info_id is None:
        log.warning(f"[priorities.harness_queue] No harness_info_id found for job {job} in task {task}")
        return 0

    return queue_counts.get(harness_info_id, 0) + 1

@alru_cache(maxsize=10000)
async def get_crs_task_metadata(pipeline: HashablePipelineSingleton, task: str, job: str) -> dict[str, str]:
    task_obj = pipeline.pipeline.tasks[task]
    project_id_repo = repo_related(task_obj, 'crs_task')
    if project_id_repo is None:
        log.warning(f"[priorities.get_crs_task_metadata] No crs_task repo found for task {task}")
        return {}
    crs_task = await project_id_repo.info(job)
    if crs_task is None:
        log.warning(f"[priorities.get_crs_task_metadata] No crs_task found for job {job} in task {task}")
        return {}
    return crs_task

@alru_cache(maxsize=10000)
async def get_fuzzing_pool_name(pipeline: HashablePipelineSingleton, task: str, job: str) -> str|None:
    crs_task = await get_crs_task_metadata(pipeline, task, job)
    #log.info(f"crs_task for {task} {job}: {crs_task}")
    if not crs_task:
        log.warning(f"[priorities.get_fuzzing_pool_name] No crs_task found for job {job} in task {task}")
        return None
    return crs_task.get('fuzzing_pool_name')


async def harness_queue(pipeline: pydatatask.Pipeline, task: str, job: str, replica: int) -> float:
    hpl = HashablePipelineSingleton(pipeline)

    try:
        # First we find the harness this task is related to
        queue_index = await get_index_of_task_in_harness_queue(
            hpl,
            task,
            job,
        )

        # TODO equalize based on number of harnesses in the task that have active jobs in the queue

        # The index should be inversely proportional to the priority addend
        return queue_index

    except Exception as e:
        import traceback
        traceback.print_exc()
        return 0.0

    finally:
        hpl.drop()

async def task_pool_labels(pipeline: pydatatask.Pipeline, task: str, job: str, replica: int) -> dict[str, str]:
    node_labels = {}

    hpl = HashablePipelineSingleton(pipeline)

    try:
        fuzzing_pool_name = await get_fuzzing_pool_name(hpl, task, job)
        #log.info(f"fuzzing_pool_name for {task} {job} --> {fuzzing_pool_name}")
        if not fuzzing_pool_name:
            log.warning(f"[priorities.task_pool_labels] No fuzzing_pool_name found for job {job} in task {task}")
            return {}
        node_labels['support.shellphish.net/task-pool'] = fuzzing_pool_name

        return node_labels
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {}

    finally:
        hpl.drop()