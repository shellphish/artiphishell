

import argparse
import logging
import os
from typing import List
from pathlib import Path

from coveragelib.parsers.line_coverage import C_LineCoverageParser_LLVMCovHTML, Java_LineCoverageParser_Jacoco
from coveragelib.trace import Tracer
import petname
from shellphish_crs_utils.function_resolver import LocalFunctionResolver, RemoteFunctionResolver
from shellphish_crs_utils.models.oss_fuzz import LanguageEnum, AugmentedProjectMetadata
from shellphish_crs_utils.models.target import HarnessInfo
from shellphish_crs_utils.oss_fuzz.instrumentation.coverage_fast import CoverageFastInstrumentation
from shellphish_crs_utils.oss_fuzz.project import InstrumentedOssFuzzProject
import yaml

import agentlib

from grammar_guy.agentic.globals import set_coverage_target, set_coverage_tracer, set_function_resolver, set_fuzzer_sync_dir, set_harness_index_key, get_function_resolver, get_coverage_tracer, set_harness_info, set_harness_info_dict
from grammar_guy.agentic.globals import set_fuzzer_sync_dirs

MODEL = {
    0: 'claude-4-sonnet',
    1: 'claude-4-sonnet',
    2: 'o3',
    3: 'claude-3.5-sonnet',
}[int(os.getenv("REPLICA_ID", "0"))]
BUDGET = 'grammar-openai-budget' if MODEL == 'o3' else 'grammar-budget'
MAX_TOKENS = 8192 if MODEL == 'claude-3.5-sonnet' else 16384

handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
handler.setFormatter(logging.Formatter("[%(levelname)s] %(asctime)s | %(message)s"))

log = logging.getLogger("grammar_guy")
log.setLevel(logging.INFO)
log.addHandler(handler)
#log.propagate = False


def run_agent(agent):
    random_project_name = 'pr-' + petname.Generate(3, '-')
    os.environ['LANGSMITH_PROJECT'] = random_project_name
    log.info(f"USING LANGCHAIN PROJECT NAME {random_project_name}")

    parser = argparse.ArgumentParser()
    parser.add_argument('--coverage-target', type=Path, required=True)
    parser.add_argument('--project-metadata', type=Path)
    parser.add_argument('--fuzzer-sync-dir', type=Path)
    parser.add_argument('--full-functions-index', type=Path)
    parser.add_argument('--full-functions-jsons', type=Path)
    # TODO(FINALDEPLOY)
    # TODO Update the budget here
    parser.add_argument('--budget-in-dollars', type=float, default=5)

    if hasattr(agent, 'add_args'):
        agent.add_args(parser)

    ARGS = parser.parse_args()

    agentlib.enable_event_dumping('./events')
    #TODO(finaldeploy): Update the budget here
    agentlib.set_global_budget_limit(
        price_in_dollars=ARGS.budget_in_dollars,
        exit_on_over_budget=True,
        lite_llm_budget_name=BUDGET,
    )
    agentlib.add_prompt_search_path(Path(__file__).parent / 'prompts')

    with open(ARGS.harness_info) as f:
        harness_info = HarnessInfo.model_validate(yaml.safe_load(f.read()))
    if ARGS.project_metadata:
        with open(ARGS.project_metadata) as f:
            project_metadata = AugmentedProjectMetadata.model_validate(yaml.safe_load(f.read()))
    else:
        project_metadata = None

    target = InstrumentedOssFuzzProject(
        CoverageFastInstrumentation(),
        ARGS.coverage_target,
        project_id=harness_info.project_id,
        augmented_metadata=project_metadata,
    )
    set_coverage_target(target)
    parser = {
        LanguageEnum.c: C_LineCoverageParser_LLVMCovHTML,
        LanguageEnum.cpp: C_LineCoverageParser_LLVMCovHTML,
        LanguageEnum.jvm: Java_LineCoverageParser_Jacoco,
    }[target.project_metadata.language]()

    set_coverage_tracer(Tracer(ARGS.coverage_target, harness_info.cp_harness_name, aggregate=True, parser=parser))
    get_coverage_tracer().instr_project.build_runner_image()
    set_fuzzer_sync_dir(ARGS.fuzzer_sync_dir)

    if ARGS.full_functions_index and ARGS.full_functions_jsons:
        set_function_resolver(LocalFunctionResolver(ARGS.full_functions_index, ARGS.full_functions_jsons))
    else:
        set_function_resolver(RemoteFunctionResolver(cp_name=harness_info.project_name, project_id=harness_info.project_id))

    if hasattr(agent, 'setup'):
        agent.setup(ARGS)

    harness_function_index_key = target.get_harness_function_index_key(harness_info.cp_harness_name, get_function_resolver())
    if not harness_function_index_key:
        raise ValueError(f'Could not find harness function {harness_info.cp_harness_name} in the function index')

    harness_function_index = get_function_resolver().get(harness_function_index_key)
    harness_target_container_path = harness_function_index.target_container_path
    harness_source_code = harness_function_index.code

    set_harness_index_key(harness_function_index_key)
    set_harness_info(harness_info)

    with get_coverage_tracer():
        agent.run(
            harness_index=harness_function_index_key,
            harness_source_code=harness_source_code,
            harness_info=harness_info,
        )

def run_agent_explore(agent):
    random_project_name = 'pr-' + petname.Generate(3, '-')
    os.environ['LANGSMITH_PROJECT'] = random_project_name
    log.info(f"USING LANGCHAIN PROJECT NAME {random_project_name}")

    parser = argparse.ArgumentParser()
    parser.add_argument('--coverage-target', type=Path, required=True)
    parser.add_argument('--project-metadata', type=Path)
    parser.add_argument('--full-functions-index', type=Path)
    parser.add_argument('--full-functions-jsons', type=Path)
    # New arguments
    parser.add_argument('--project-harness-metadata', type=Path)
    parser.add_argument('--project-harness-metadata-id', type=Path)
    parser.add_argument('--target-split-metadata', type=Path, required=True, help="Path to the target split metadata file.")
    parser.add_argument('--events-dir', type=Path, help='Directory to store events', required=False, default='./events')
    # TODO(FINALDEPLOY)
    # TODO Update the budget here
    parser.add_argument('--budget-in-dollars', type=float, default=99999999)

    if hasattr(agent, 'add_args'):
        agent.add_args(parser)

    ARGS = parser.parse_args()
    # New check
    if not os.path.exists(ARGS.events_dir):
        os.makedirs(ARGS.events_dir, exist_ok=True)
    agentlib.enable_event_dumping(ARGS.events_dir)
    #TODO(finaldeploy): Update the budget here
    agentlib.set_global_budget_limit(
        price_in_dollars=ARGS.budget_in_dollars,
        exit_on_over_budget=True,
        lite_llm_budget_name=BUDGET,
    )
    agentlib.add_prompt_search_path(Path(__file__).parent / 'prompts')

    # with open(ARGS.harness_info) as f:
    #     harness_info = HarnessInfo.model_validate(yaml.safe_load(f.read()))

    if ARGS.project_metadata:
        with open(ARGS.project_metadata) as f:
            project_metadata = AugmentedProjectMetadata.model_validate(yaml.safe_load(f.read()))
    else:
        project_metadata = None
    # New variables
    project_harness_metadata_id = ARGS.project_harness_metadata_id
    project_harness_metadata = None
    target_split_metadata = None
    harness_info_files = []
    harness_info_dict = {}

    # New setup
    with open(ARGS.target_split_metadata, 'r') as f:
        target_split_metadata = yaml.safe_load(f)
        project_harness_metadata = target_split_metadata['project_harness_metadatas'][str(ARGS.project_harness_metadata_id)]

    for harness_info_id, harness_info in target_split_metadata['harness_infos'].items():
            # GET might break because of missing values - not list in pydantic model
            if harness_info['cp_harness_name'] == project_harness_metadata['cp_harness_name']:
                hi = HarnessInfo.model_validate(harness_info)
                harness_info_files.append(hi)
                harness_info_dict[harness_info_id] = hi


    # Set and make afl_synch_dirs and fuzzer_sync_dirs
    fuzzer_sync_dirs = set_directories(project_harness_metadata, harness_info_dict)

    target = InstrumentedOssFuzzProject(
        CoverageFastInstrumentation(),
        ARGS.coverage_target,
        project_id=project_harness_metadata['project_id'],
        augmented_metadata=project_metadata,
    )
    set_coverage_target(target)
    parser = {
        LanguageEnum.c: C_LineCoverageParser_LLVMCovHTML,
        LanguageEnum.cpp: C_LineCoverageParser_LLVMCovHTML,
        LanguageEnum.jvm: Java_LineCoverageParser_Jacoco,
    }[target.project_metadata.language]()

    set_coverage_tracer(Tracer(ARGS.coverage_target, project_harness_metadata['cp_harness_name'], aggregate=True, parser=parser))
    get_coverage_tracer().instr_project.build_runner_image()
    # Changed to multiple dirs - function also changed @ import location
    set_fuzzer_sync_dirs(fuzzer_sync_dirs)
    set_harness_info_dict(harness_info_dict)

    if ARGS.full_functions_index and ARGS.full_functions_jsons:
        set_function_resolver(LocalFunctionResolver(ARGS.full_functions_index, ARGS.full_functions_jsons))
    else:
        set_function_resolver(RemoteFunctionResolver(cp_name=project_harness_metadata['project_name'], project_id=project_harness_metadata['project_id']))

    if hasattr(agent, 'setup'):
        agent.setup(ARGS)

    # harness_info.cp_harnessname --> project_harness_metadata['cp_harness_name']
    harness_function_index_key = target.get_harness_function_index_key(project_harness_metadata['cp_harness_name'], get_function_resolver())
    if not harness_function_index_key:
        raise ValueError(f"Could not find harness function {project_harness_metadata['cp_harness_name']} in the function index")

    harness_function_index = get_function_resolver().get(harness_function_index_key)
    harness_target_container_path = harness_function_index.target_container_path
    harness_source_code = harness_function_index.code

    set_harness_index_key(harness_function_index_key)
    # set_harness_info(harness_info)

    with get_coverage_tracer():
        agent.run(
            harness_index=harness_function_index_key,
            harness_source_code=harness_source_code,
            # harness_info=harness_info, we don't have harness_infos
        )

def set_directories(project_harness_metadata, harness_info_dict) -> List[Path]:
    fuzzer_sync_dirs = []

    replica_id = os.environ.get('REPLICA_ID', '0')
    task_name = os.environ.get('TASK_NAME', '')
    job_id = os.environ.get('JOB_ID', '')
    project_id = project_harness_metadata['project_id']

    for harness_info_id, harness_info in harness_info_dict.items():
        project_name = project_harness_metadata['project_name']
        cp_harness_name = harness_info.cp_harness_name

        fuzzer_sync_dir = Path(f"/shared/fuzzer_sync/{project_name}-{cp_harness_name}-{harness_info_id}/sync-{task_name.replace('_', '-')}-{replica_id}")
        os.makedirs(fuzzer_sync_dir / 'queue', exist_ok=True)

        fuzzer_sync_dirs.append(fuzzer_sync_dir)

    return fuzzer_sync_dirs