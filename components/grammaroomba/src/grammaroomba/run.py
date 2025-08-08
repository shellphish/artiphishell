"""Grammar Guy Agentic Explorer - compact runner"""

import time
from pathlib import Path
import argparse, logging, os, yaml

# third‑party / local libs
import agentlib
from coveragelib.trace import Tracer
from coveragelib.parsers.line_coverage import C_LineCoverageParser_LLVMCovHTML, Java_LineCoverageParser_Jacoco
from permanence.client import PermanenceClient
from shellphish_crs_utils.function_resolver import RemoteFunctionResolver
from shellphish_crs_utils.oss_fuzz.instrumentation.coverage_fast import CoverageFastInstrumentation
from shellphish_crs_utils.oss_fuzz.project import InstrumentedOssFuzzProject
from shellphish_crs_utils.models.oss_fuzz import LanguageEnum, AugmentedProjectMetadata
from shellphish_crs_utils.models.target import HarnessInfo
from crs_telemetry.utils import init_otel, get_otel_tracer, status_ok, init_llm_otel
from grammaroomba.globals import GLOBALS
from grammaroomba.ranker import *  # noqa: F401,F403 - keep behaviour
from grammaroomba.functions import FunctionMetaStack  # noqa: F401 - future use
from grammaroomba.roomba import Grammaroomba

init_otel("grammar-guy-agentic-explorer", "input-generation", "llm_grammar_generation")
init_llm_otel()
tracer = get_otel_tracer()
log = logging.getLogger("grammaroomba.run")

def set_directories(harness_info_dict: dict[str, HarnessInfo]):
    task_name = os.environ.get('TASK_NAME', 'grammar_roomba')

    try:
        replica_id = int(os.environ['REPLICA_ID'])
    except Exception as e:
        log.warning(f"Could not parse REPLICA_ID from environment: {e}")
        replica_id = 0

    for harness_info_id, harness_info in harness_info_dict.items():
        project_name = harness_info.project_name
        cp_harness_name = harness_info.cp_harness_name
        fuzzer_sync_dir = Path(f"/shared/fuzzer_sync/{project_name}-{cp_harness_name}-{harness_info_id}/sync-{task_name.replace('_', '-')}-{replica_id}")
        # Create directories if they don't exist
        os.makedirs(fuzzer_sync_dir, exist_ok=True)

        GLOBALS.fuzzer_sync_dirs.append(fuzzer_sync_dir)

def setup() -> bool:
    try:
        logging.basicConfig(level=logging.INFO)
        p = argparse.ArgumentParser("Grammar Guy")
        p.add_argument("--target-shared-dir", type=Path, required=True)
        p.add_argument("--target-split-metadata", type=Path, required=True)
        p.add_argument("--project-harness-metadata-id", required=True)
        p.add_argument("--project-harness-metadata", type=Path, required=True)
        p.add_argument("--project-metadata", required=True)
        p.add_argument("--events-dir", default="./events")
        delta = os.getenv("DELTA_MODE") == "True"
        if delta:
            p.add_argument("--commit-functions-index")
        args = p.parse_args()

        GLOBALS.target_shared_dir = args.target_shared_dir
        GLOBALS.function_ranker = FunctionRanker()

        # project metadata
        if args.project_metadata:
            meta = yaml.safe_load(Path(args.project_metadata).read_text())
            GLOBALS.project_metadata = AugmentedProjectMetadata.model_validate(meta)
        else:
            GLOBALS.project_metadata = None

        # split metadata / harness info
        GLOBALS.project_harness_metadata_id = args.project_harness_metadata_id
        split_meta = yaml.safe_load(Path(args.target_split_metadata).read_text())
        GLOBALS.target_split_metadata = split_meta
        GLOBALS.project_harness_metadata = split_meta["project_harness_metadatas"][GLOBALS.project_harness_metadata_id]
        for hi_id, hi in split_meta["harness_infos"].items():
            if hi["cp_harness_name"] == GLOBALS.project_harness_metadata["cp_harness_name"]:
                h = HarnessInfo.model_validate(hi)
                GLOBALS.harness_info_files.append(h)
                GLOBALS.harness_info_dict[hi_id] = h
        
        set_directories(GLOBALS.harness_info_dict)

        # agentlib
        agentlib.enable_event_dumping(str(args.events_dir))
        # TODO(finaldeploy)
        agentlib.set_global_budget_limit(price_in_dollars=9999999999, exit_on_over_budget=True, lite_llm_budget_name="grammar-openai-budget")
        agentlib.add_prompt_search_path(Path(__file__).parent / "agents" / "prompts")

        # instrumented target
        GLOBALS.target = InstrumentedOssFuzzProject(CoverageFastInstrumentation(), GLOBALS.target_shared_dir, project_id=GLOBALS.project_harness_metadata["project_id"], augmented_metadata=GLOBALS.project_metadata)
        GLOBALS.parser = {
            LanguageEnum.c: C_LineCoverageParser_LLVMCovHTML,
            LanguageEnum.cpp: C_LineCoverageParser_LLVMCovHTML,
            LanguageEnum.jvm: Java_LineCoverageParser_Jacoco,
        }[GLOBALS.target.project_metadata.language]()
        GLOBALS.function_resolver = RemoteFunctionResolver(cp_name=GLOBALS.project_harness_metadata["project_name"], project_id=GLOBALS.project_harness_metadata["project_id"])
        if not GLOBALS.permanence_client and GLOBALS.function_resolver:
            GLOBALS.permanence_client = PermanenceClient(function_resolver=GLOBALS.function_resolver)

        # harness key
        GLOBALS.cp_harness_name = GLOBALS.project_harness_metadata["cp_harness_name"]
        GLOBALS.harness_function_index_key = GLOBALS.target.get_harness_function_index_key(GLOBALS.project_harness_metadata["cp_harness_name"], GLOBALS.function_resolver)
        if not GLOBALS.harness_function_index_key:
            raise ValueError("Harness function not found")
        
        # load commit index keys (if any)
        if delta: 
            index: Dict = yaml.safe_load(Path(args.commit_functions_index).read_text())
            for commit_name, commit_dict in index.items():
                GLOBALS.diff_functions.extend(commit_dict.keys())


        # rank functions
        start_time_rank = time.time()
        for k in (GLOBALS.function_resolver.keys() if GLOBALS.function_resolver else []):
            ranked = GLOBALS.function_ranker.rank_functions([(k, GLOBALS.function_resolver.get(k).code)])
            if ranked:
                GLOBALS.function_ranking[k] = ranked[0]
            else:
                log.warning("skip %s", k)

        log.info(f"It took us {time.time() - start_time_rank:.2f} seconds to rank {len(GLOBALS.function_ranking)} functions.")
    except Exception as e:
        log.error("setup: %s", e)
        return False
    return True


def run_roomba():
    with Tracer(GLOBALS.target_shared_dir, GLOBALS.project_harness_metadata["cp_harness_name"], aggregate=True, parser=GLOBALS.parser) as tracer:
        GLOBALS.tracer = tracer
        tracer.instr_project.build_runner_image()
        GLOBALS.harness_source_code = GLOBALS.function_resolver.get(GLOBALS.harness_function_index_key).code
        log.info("running roomba")
        assert Grammaroomba(tracer).run() is None


def main():
    assert setup(), "setup failed"
    run_roomba()
    log.info("done")


if __name__ == "__main__":
    with tracer.start_as_current_span("grammaroomba.runner") as span:  # type: ignore[attr-defined]
        main()
        span.set_status(status_ok())