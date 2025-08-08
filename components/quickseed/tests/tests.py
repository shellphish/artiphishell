import logging
import os
import queue
import shutil
import tempfile
import unittest
import subprocess
import textwrap
from pathlib import Path
from typing import Optional
from collections import defaultdict

from jinja2 import Template
import json
import random
import string
import tempfile
import networkx as nx
import pickle

from libcodeql.client import CodeQLClient
from coveragelib import Tracer
from aixcc_test_utils import *

from QuickSeed.data import TriageCoverage

from QuickSeed.parser import CallGraphParser, CodeQLStruct, SinkType, CoverageAnalysis,\
    ReflectionParser, CodeQLReportParser
from QuickSeed.manager import Scheduler, Initializer, PostProcessor
from QuickSeed.verifier import SeedTriage

from QuickSeed.llm import BlockerAnalyzer, SeedGenerator, SeedGeneratorTask, BlockerAnalyzerTask, SinkIdentifier, SinkIdentifierTask

from QuickSeed.utils import setup_oss_fuzz_debug_build, run_crash_input
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject

from test_utils import TARGET, JAZZER_SANITIZER, QUERY_PATH, QUERY_TEMPLATES_PATH, not_run_on_ci, run_build_command, \
    run_codeql_command, run_build_image_command, check_image_exists


from aixcc_test_utils import *

import QuickSeed

_l = logging.getLogger("QuickSeed")
_l.setLevel(logging.DEBUG)

def setup_aicc_target(url: str, target_dir: Path, commit: Optional[str]=None, build=False) -> Path:
    import git
    if not target_dir.exists():
        target_dir.mkdir(parents=True)
        git.Repo.clone_from(url, target_dir)
        if commit:
            repo = git.Repo(str(target_dir))
            repo.git.checkout(commit)
        if "cp" in target_dir.name:
            subprocess.run(
                ["make", "cpsrc-prepare"],
                cwd=str(target_dir),
                check=True,
                )
    if build:
        subprocess.run(
            ["make", "docker-pull"],
            cwd=str(target_dir),
            check=True,
        )
        subprocess.run(
            ["./run.sh", "build"],
            cwd=str(target_dir),
            check=True
        )
    return target_dir

def run_build_from_backup(backup_data_dir: Path) -> None:
    pass


# def build_aicc_target(target_dir: Path) -> None:
#     subprocess.run(
#         ["make", "docker-pull"],
#         cwd=str(target_dir),
#         check=True,
#     )
#     subprocess.run(
#         ["make", "cpsrc-prepare"],
#         cwd=str(target_dir),
#         check=True,
#     )
#     subprocess.run(
#         ["./run.sh", "build"],
#         cwd=str(target_dir),
#         check=True
#     )

class TestQuickSeed(unittest.TestCase):
    def test_version(self):
        self.assertEqual(QuickSeed.__version__, "0.0.1")

    @not_run_on_ci
    def test_codeql_report_parser(self):
        target_dir = TARGET / "zip4j"
        ql_record_struct = [
            CodeQLStruct.SOURCE_NAME, CodeQLStruct.TARGET_NAME, 
            CodeQLStruct.CALL_FILEPATH, CodeQLStruct.CALL_LINENO, 
            CodeQLStruct.SOURCE_FILEPATH, CodeQLStruct.SOURCE_LINENO, 
            CodeQLStruct.TARGET_FILEPATH, CodeQLStruct.TARGET_LINENO, 
            CodeQLStruct.SANITIZER_NAME, CodeQLStruct.SINK_LOCATION
        ]
        # codeql_report = target_dir / "demo_codeql_report.yaml"
        project_id = "2"
        codeql_report = {}
        client = CodeQLClient()
        for ql_file in QUERY_PATH.iterdir():
            with open(ql_file, "r") as f:
                query = f.read()
            # FIXME: project id
            query_result = client.query({
                "cp_name": "zip4j",
                "project_id": project_id,
                "query": query
            })
            codeql_report[ql_file.stem] = query_result
        # codeql_report_parser = CodeQLReportParser(codeql_report, ql_record_struct)

        # assert len(codeql_report_parser.sanitizer_nodes)==366
        # assert len(codeql_report_parser.sanitizer_edges)==760

        other_ql_record_struct = {
            "ReflectionCall": 
            [
                CodeQLStruct.REFLECTION_CALL_METHOD_NAME, CodeQLStruct.UNDEFINED,
                CodeQLStruct.REFLECTION_CALL_METHOD_LOCATION, CodeQLStruct.REFLECTION_CALL_LOCATION
            ],
            "AbstractOverride":
            [
                CodeQLStruct.SOURCE_NAME, CodeQLStruct.SOURCE_LOCATION,
                CodeQLStruct.TARGET_NAME, CodeQLStruct.TARGET_LOCATION
            ]
        }

        # codeql_report = target_dir / "incomplete_codeql_report.yaml"
        codeql_report_parser = CodeQLReportParser(codeql_report, ql_record_struct, other_ql_record_struct)



        assert len(codeql_report_parser.sanitizer_nodes) > 366
        assert len(codeql_report_parser.sanitizer_edges) > 760
        # assert codeql_report_parser.sanitizer_sink_functions == ['exec', 'getRuntime']


    @not_run_on_ci
    def test_zip4j_call_graph_parser(self):
        target_dir = TARGET / "zip4j"
        func_index_path = target_dir / "function_indices.json"
        func_dir = target_dir / "func_json_dir"
        harness_name = "Zip4jFuzzer"
        project_id = "2"
        codeql_report = {}
        client = CodeQLClient()
        for ql_file in QUERY_PATH.iterdir():
            if "FileSystem" in str(ql_file):
                continue
            with open(ql_file, "r") as f:
                query = f.read()
            # FIXME: project id
            query_result = client.query({
                "cp_name": "zip4j",
                "project_id": project_id,
                "query": query
            })
            codeql_report[ql_file.stem] = query_result

        cp_root = target_dir / "zip4j-cp"
        harness_filepath = cp_root / "Zip4jFuzzer.java"
        source_root = target_dir / "zip4j-source"
        language = "java"

        # zip4j_project = setup_oss_fuzz(cp_root, source_root)

        ql_record_struct = [
            CodeQLStruct.SOURCE_NAME, CodeQLStruct.TARGET_NAME,
            CodeQLStruct.CALL_FILEPATH, CodeQLStruct.CALL_LINENO,
            CodeQLStruct.SOURCE_FILEPATH, CodeQLStruct.SOURCE_LINENO,
            CodeQLStruct.TARGET_FILEPATH, CodeQLStruct.TARGET_LINENO,
            CodeQLStruct.SANITIZER_NAME, CodeQLStruct.SINK_LOCATION
        ]
        other_ql_record_struct = {
            "ReflectionCall": 
            [
                CodeQLStruct.REFLECTION_CALL_METHOD_NAME, CodeQLStruct.UNDEFINED,
                CodeQLStruct.REFLECTION_CALL_METHOD_LOCATION, CodeQLStruct.REFLECTION_CALL_LOCATION
            ],
            "AbstractOverride":
            [
                CodeQLStruct.SOURCE_NAME, CodeQLStruct.SOURCE_LOCATION,
                CodeQLStruct.TARGET_NAME, CodeQLStruct.TARGET_LOCATION
            ]
        }
        codeql_report_parser = CodeQLReportParser(
            codeql_report,
            ql_record_struct,
            other_ql_record_struct
        )

        # program = Program(**program_info)
        call_graph_parser = CallGraphParser(
            cp_root,
            codeql_report_parser,
            language="java",
            source=['fuzzerTestOneInput'],
            source_harness_filepath=[harness_filepath],
            sink=codeql_report_parser.sanitizer_sink_functions,
            sink_type=SinkType.SANITIZER,
            function_json_dir=target_dir /  "func_json_dir",
            func_indexer=target_dir / "function_indices.json"
        )

        for node in call_graph_parser.nodes.values():
            _l.info(f"The function source code is {node.function_name}")
            _l.info(f"The function id is {node.id}")

        for node in call_graph_parser.nodes.values():
            if node.function_name == "fuzzerTestOneInput":
                assert node.function_code
                break
        paths = call_graph_parser.get_all_shortest_paths_from_source_to_sink()

        # path = [  
        #     {
        #         "function_name": "fuzzerTestOneInput",
        #         "filepath": "/src/Zip4jFuzzer.java"
        #     },
        #     {
        #         "function_name": "extractAll",
        #         "filepath": "/src/zip4j/src/main/java/net/lingala/zip4j/ZipFile.java",
        #     },
        #     {
        #         "function_name": "execute",
        #         "filepath": "/src/zip4j/src/main/java/net/lingala/zip4j/tasks/AsyncZipTask.java",
        #     },
        #     {
        #         "function_name": "performTaskWithErrorHandling",
        #         "filepath": "/src/zip4j/src/main/java/net/lingala/zip4j/tasks/AsyncZipTask.java"
        #     },
        #     {
        #         "function_name": "executeTask",
        #         "filepath": "/src/zip4j/src/main/java/net/lingala/zip4j/tasks/AsyncZipTask.java",
        #     },
        #     {
        #         "function_name": "executeTask",
        #         "filepath": "/src/zip4j/src/main/java/net/lingala/zip4j/tasks/ExtractAllFilesTask.java",
        #     },
        #     {
        #         "function_name": "extractFile",
        #         "filepath": "/src/zip4j/src/main/java/net/lingala/zip4j/tasks/AbstractExtractFileTask.java"
        #     },
        #     {
        #         "function_name": "assertCanonicalPathsAreSame",
        #         "filepath": "/src/zip4j/src/main/java/net/lingala/zip4j/tasks/AbstractExtractFileTask.java"
        #     }
        # ]


    # def test_jenkins_control_flow_graph_41(self):
    #     target_dir = TARGET / "jenkins"
    #     program_info = {
    #         "src_root": target_dir / "src" / "plugins/pipeline-util-plugin",
    #         "report": target_dir / "cfg_result_execFortyOneUtils_v2.json",
    #         "lang": "java"
    #     }
    #     ql_record_struct = [
    #         CodeQLStruct.SOURCE_NODE_EXPR, CodeQLStruct.TARGET_NODE_EXPR, \
    #         CodeQLStruct.SOURCE_LOCATION, CodeQLStruct.TARGET_LOCATION]
    #     program = Program(**program_info)

    #     control_flow_parser = ControlFlowGraphParser(program, ql_record_struct)
    #     for node in control_flow_parser.nodes:
    #         if len(node.next_nodes) > 1:
    #             _l.info(f"Node {node.id} has expr {node.expr} and location {node.location} with next nodes {node.next_nodes}")
    #     # control_flow_parser.visualize_graph('expr')
    #     control_flow_parser.merge_nodes_with_same_location()
    #     assert len(control_flow_parser.nodes) == 17
    #     assert len(control_flow_parser.edges) == 20
    #     # control_flow_parser.visualize_graph('expr')

    # def test_nginx_cpv9_call_graph_parser(self):
    #     target_dir = TARGET / "nginx"
    #     nginx_src_repo = target_dir / "challenge-004-nginx-source"
    #     if not nginx_src_repo.exists():
    #         setup_aicc_target(
    #             "https://github.com/aixcc-public/challenge-004-nginx-source.git",
    #             nginx_src_repo
    #             )
    #     program_info = {
    #         "src_root": nginx_src_repo,
    #         "report": target_dir / "cpv9_call_to_ngx_black_list_remove_v2.json",
    #         # "report": target_dir /"cpv9_call_to_ngx_process_white_list.json",
    #         "lang": "c"
    #     }
    #     ql_record_struct = [
    #         CodeQLStruct.SOURCE_NAME, CodeQLStruct.TARGET_NAME, \
    #         CodeQLStruct.SOURCE_LOCATION, CodeQLStruct.TARGET_LOCATION, \
    #         CodeQLStruct.SOURCE_BODY_LOCATION, CodeQLStruct.TARGET_BODY_LOCATION
    #     ]
    #     program = Program(**program_info)
    #     call_graph_parser = CallGraphParser(
    #         program,
    #         ql_record_struct,
    #         source = ['LLVMFuzzerTestOneInput'],
    #         sink=['ngx_black_list_remove'],
    #         # sink = ['ngx_http_process_white_list'],
    #         sink_type=SinkType.COMMIT,
    #         antlr=target_dir / "backup-full-nginx-11212282703" / "func_json_dir",
    #         func_indexer=target_dir / "backup-full-nginx-11212282703" / "function_indices.json"
    #     )

    # @not_run_on_ci
    # def test_nginx_cpv12_call_graph_parser_and_paths(self):
    #     target_dir = TARGET / "nginx"
    #     nginx_src_repo = target_dir / "challenge-004-nginx-source"
    #     if not nginx_src_repo.exists():
    #         setup_aicc_target(
    #             "https://github.com/aixcc-public/challenge-004-nginx-source.git",
    #             nginx_src_repo
    #         )
    #     program_info = {
    #         "src_root": nginx_src_repo,
    #         "report": target_dir / "cpv12_call_to_ngx_sendfile_r.json",
    #         "lang": "c"
    #     }
    #     ql_record_struct = [
    #         CodeQLStruct.SOURCE_NAME, CodeQLStruct.TARGET_NAME, \
    #         CodeQLStruct.SOURCE_LOCATION, CodeQLStruct.TARGET_LOCATION, \
    #         CodeQLStruct.SOURCE_BODY_LOCATION, CodeQLStruct.TARGET_BODY_LOCATION
    #     ]
    #     program = Program(**program_info)
    #     call_graph_parser = CallGraphParser(
    #         program,
    #         ql_record_struct,
    #         source=['LLVMFuzzerTestOneInput'],
    #         sink=['ngx_sendfile_r'],
    #         sink_type=SinkType.COMMIT,
    #         antlr=target_dir / "backup-full-nginx-11212282703" / "func_json_dir",
    #         func_indexer=target_dir / "backup-full-nginx-11212282703" / "function_indices.json"
    #     )
    #     for sink_id in call_graph_parser.sink_node_ids:
    #         paths = call_graph_parser.all_paths_ends_with_sink(sink_id)
    #         for path in paths:
    #             _l.info(f"Path is {path}")
        
    #     q = queue.Queue()
    #     benign_dir = tempfile.mkdtemp(prefix="benign_", dir="/tmp")
    #     crash_dir = tempfile.mkdtemp(prefix="crash_", dir="/tmp")
    #     os.makedirs(benign_dir, exist_ok=True)
    #     os.makedirs(crash_dir, exist_ok=True)
    #     producer_codeql = CProducer(
    #         call_graph_parser,
    #         q,
    #         model="gpt-4o",
    #         name="C seed generator"
    #     )
    #     producer_codeql.start()
    #     producer_codeql.wait_finish()

    #     assert not q.empty()
    #     task = q.get()
    #     triage_queue = queue.Queue()
    #     _l.debug(f"task is {task}")
    #     model = task.use_model_name
    #     consumer_llm = SeedGeneratorConsumer(
    #         model, 
    #         q, 
    #         benign_dir, 
    #         crash_dir, 
    #         nginx_src_repo, 
    #         triage_queue,
    #         name="C seed generator", 
    #         triage=True, 
    #         language="c"
    #         )
    #     consumer_proxy = ConsumerProxy(q)
    #     consumer_proxy.add_worker(consumer_llm)
    #     consumer_proxy.start()
    #     consumer_proxy.wait_finish()
    #     _l.debug(f"crash seed is saved to {crash_dir}")
    #     _l.debug(f"benign seed is saved to {benign_dir}")
    #     assert len(os.listdir(benign_dir)) > 0

    # @not_run_on_ci
    # def test_nginx_cpv9_seed_gen(self):
    #     target_dir = TARGET / "nginx"
    #     nginx_src_repo = target_dir / "targets-semis-aixcc-sc-challenge-004-full-nginx-cp"
    #     if not nginx_src_repo.exists():
    #         setup_aicc_target(
    #             "https://github.com/shellphish-support-syndicate/targets-semis-aixcc-sc-challenge-004-full-nginx-cp.git",
    #             nginx_src_repo
    #             )
    #     program_info = {
    #         "src_root": nginx_src_repo,
    #         "report": target_dir / "cpv9_call_to_ngx_black_list_remove_v2.json",
    #         "lang": "c"
    #     }
    #     ql_record_struct = [
    #         CodeQLStruct.SOURCE_NAME, CodeQLStruct.TARGET_NAME, \
    #         CodeQLStruct.SOURCE_LOCATION, CodeQLStruct.TARGET_LOCATION, \
    #         CodeQLStruct.SOURCE_BODY_LOCATION, CodeQLStruct.TARGET_BODY_LOCATION
    #     ]
    #     program = Program(**program_info)

    #     call_graph_parser = CallGraphParser(
    #         program,
    #         ql_record_struct,
    #         source = ['LLVMFuzzerTestOneInput'],
    #         sink=['ngx_black_list_remove'],
    #         sink_type=SinkType.COMMIT,
    #         antlr=target_dir / "backup-full-nginx-11212282703" / "func_json_dir",
    #         func_indexer=target_dir / "backup-full-nginx-11212282703" / "function_indices.json"
    #     )

    #     q = queue.Queue()
    #     benign_dir = tempfile.mkdtemp(prefix="benign_", dir="/tmp")
    #     crash_dir = tempfile.mkdtemp(prefix="crash_", dir="/tmp")
    #     os.makedirs(benign_dir, exist_ok=True)
    #     os.makedirs(crash_dir, exist_ok=True)
    #     producer_codeql = CProducer(
    #         call_graph_parser,
    #         q,
    #         model="gpt-4o",
    #         name="C seed generator"
    #     )
    #     producer_codeql.start()
    #     producer_codeql.wait_finish()

    #     assert not q.empty()
    #     task = q.get()
    #     _l.debug(f"task is {task}")
    #     model = task.use_model_name
    #     consumer_llm = SeedGeneratorConsumer(
    #         model, 
    #         q, 
    #         benign_dir, 
    #         crash_dir, 
    #         nginx_src_repo, 
    #         name="C seed generator", 
    #         triage=True, 
    #         language="c"
    #         )
    #     consumer_proxy = ConsumerProxy(q)
    #     consumer_proxy.add_worker(consumer_llm)
    #     consumer_proxy.start()
    #     consumer_proxy.wait_finish()
    #     _l.debug(f"crash seed is saved to {crash_dir}")
    #     _l.debug(f"benign seed is saved to {benign_dir}")
    #     assert len(os.listdir(benign_dir)) > 0

    def test_mock_cp_java_end_to_end(self):
        target_dir = TARGET / "mock-cp-java"
        func_index_path = target_dir / "function_indices.json"
        func_dir = target_dir / "func_json_dir"
        aggregated_harness_infos = target_dir / "aggregated_harness_info.yaml"
        project_id = "1"
        codeql_report = {}
        debug_build = Path(os.getenv("DEBUG_BUILD"))
        coverage_build = Path(os.getenv("COVERAGE_BUILD"))
        assert debug_build.exists()
        assert coverage_build.exists()
        cp_root = target_dir / "mock-cp-java"
        source_root = target_dir / "shellphish-mock-java"

        codeql_report = target_dir / "codeql_report.yaml"
        # coverage_build = target_dir / "coverage_build"
        database_path = target_dir / "codeql-database.tar.gz"
        # coverage_build_target = "/shared/quickseed/coverage-build/mock-cp-java"
        # if not check_image_exists("shellphish-oss-fuzz-builder-shellphish-mock-cp-java--libfuzzer"):
        #     _l.debug(f"Building image shellphish-oss-fuzz-builder-shellphish-mock-cp-java--libfuzzer")
        #     run_build_command(debug_build, source_root, "address", "libfuzzer", project_id)
        # if not check_image_exists("shellphish-oss-fuzz-runner-mock-cp-javar") or \
        #     not check_image_exists("shellphish-oss-fuzz-builder-mock-cp-java"):
        #     _l.debug(f"Building image libfuzzer builder and runner image")
        #     run_build_image_command(cp_root, "libfuzzer")
        assert check_image_exists("shellphish-oss-fuzz-runner-mock-cp-java")
        # if not check_image_exists("shellphish-oss-fuzz-builder-shellphish-mock-cp-java--coverage_fast"):
        #     _l.debug(f"Building image shellphish-oss-fuzz-builder-shellphish-mock-cp-java--coverage_fast")
        #     run_build_command(coverage_build, source_root, "coverage", "coverage_fast", project_id)
        # if not check_image_exists("shellphish-oss-fuzz-runner-mock-cp-java--coverage_fast") or \
        #     not check_image_exists("shellphish-oss-fuzz-builder-mock-cp-java--coverage_fast"):
        #     _l.debug(f"Building image shellphish-oss-fuzz-runner-mock-cp-java--coverage_fast")
        #     run_build_image_command(cp_root, "coverage_fast")
        # Docker pull pre-built image to save time
        assert check_image_exists("shellphish-oss-fuzz-runner-mock-cp-java--coverage_fast")
        # run_build_command(cp_root, source_root, "address", "libfuzzer", project_id)
        # run_build_image_command(cp_root, "libfuzzer")
        # run_codeql_command(database_path, cp_root.name, project_id)
        quickseed = os.getenv("QUICKSEED_PATH")
        full_command = textwrap.dedent(f'''
                {quickseed} --source-root {source_root} \
                --target-root {cp_root} \
                --func-dir {func_dir} \
                --func-index {func_index_path} \
                --harness-infos {aggregated_harness_infos} \
                --project-id {project_id} \
                --debug-build-target {debug_build} \
                --codeql-report {codeql_report} \
                --coverage-build-target {coverage_build} \
                --local-run
                ''')

        
        commands = []
        for cmd in full_command.split("\n"):
            if not cmd:
                continue
            split_cmds = cmd.split(" ")
            for scmd in split_cmds:
                if scmd:
                    commands.append(scmd)

        _l.debug(f"commands are {commands}")

        proc = subprocess.run(commands)
        _l.debug(f"return code is {proc.returncode}")
        assert proc.returncode == 0
        crash_seeds_dir = Path(os.getenv("CRASH_DIR_PASS_TO_POV"))
        harness_dump_name = "mock-cp-java-Harness-0875ccb6b55bb773d02f9babc4e3f1e3"
        benign_sync_seeds_dir = Path(f"/shared/fuzzer_sync/{harness_dump_name}/sync-quickseed/queue/")
        crash_seeds_num = len(os.listdir(crash_seeds_dir))
        benign_seeds_num = len(os.listdir(benign_sync_seeds_dir))
        assert benign_seeds_num+crash_seeds_num >= 5
        _l.info(f"we generate {crash_seeds_num} crash seeds")

    @not_run_on_ci
    def test_mock_cp_java_produce(self):
        target_dir = TARGET / "mock-cp-java"
        func_index_path = target_dir / "function_indices.json"
        func_dir = target_dir / "func_json_dir"
        harness_name = "Harness"
        project_id = "1"
        codeql_report = {}
        jazzer_json_filepath = JAZZER_SANITIZER

        

        client = CodeQLClient()
        for ql_file in QUERY_PATH.iterdir():
            with open(ql_file, "r") as f:
                query = f.read()
            # FIXME: project id
            query_result = client.query({
                "cp_name": "mock-cp-java",
                "project_id": project_id,
                "query": query
            })
            codeql_report[ql_file.stem] = query_result

        cp_root = target_dir / "mock-cp-java"
        harness_filepath = cp_root / "Harness.java"
        source_root = target_dir / "mock-cp-java-source"
        # source_root = Path("shared/mock-cp-java-source")
        language = "java"

        shared_oss_fuzz_target = "/shared/mock-cp-java"
        # setup_coverage_target(shared_oss_fuzz_target, source_root)

        mockcp_java_project = setup_oss_fuzz_debug_build(cp_root, source_root)



        ql_record_struct = [
            CodeQLStruct.SOURCE_QUALIFIED_NAME, CodeQLStruct.TARGET_QUALIFIED_NAME,
            CodeQLStruct.CALL_FILEPATH, CodeQLStruct.CALL_LINENO,
            CodeQLStruct.SOURCE_FILEPATH, CodeQLStruct.SOURCE_LINENO,
            CodeQLStruct.TARGET_FILEPATH, CodeQLStruct.TARGET_LINENO,
            CodeQLStruct.SANITIZER_NAME, CodeQLStruct.SINK_QUALIFIED_NAME
        ]
        other_ql_record_struct = {
            "ReflectionCall": 
            [
                CodeQLStruct.REFLECTION_CALL_METHOD_NAME, CodeQLStruct.UNDEFINED,
                 CodeQLStruct.REFLECTION_CALL_METHOD_LOCATION, CodeQLStruct.REFLECTION_CALL_LOCATION
            ],
            "AbstractOverride":
            [
                CodeQLStruct.SOURCE_NAME, CodeQLStruct.SOURCE_LOCATION,
                CodeQLStruct.TARGET_NAME, CodeQLStruct.TARGET_LOCATION
            ]
        }
        codeql_report_parser = CodeQLReportParser(
            codeql_report,
            ql_record_struct,
            other_ql_record_struct
        )

        # program = Program(**program_info)
        call_graph_parser = CallGraphParser(
            cp_root,
            codeql_report_parser,
            language=language,
            source=['fuzzerTestOneInput'],
            source_harness_filepath=[harness_filepath],
            sink=codeql_report_parser.sanitizer_sink_functions,
            function_json_dir=func_dir,
            func_indexer=func_index_path,
            codeql_client=client,
            project_id=project_id,
            source_root=source_root,
        )
        scheduler = Scheduler(max_workers=2)

        initializer = Initializer(
            scheduler, 
            call_graph_parser, 
            reflection_parser="whatever", 
            jazzer_json = jazzer_json_filepath,
            harness_name=harness_name,
            harness_path = harness_filepath,
            available_models=["gpt-4o", "claude-3.5-sonnet"],
            )
        scheduler.start()
        initializer.submit_tasks_to_scheduler()

        scheduler.wait_finish()
        assert scheduler.result_queue.qsize() == 5
        # for _ in range(scheduler.result_queue.qsize()):
        #     result = scheduler.result_queue.get()
        #     assert result[0]
        #     _l.debug(f"result is {result}")

        
        random_string = ''.join(random.choices(string.ascii_lowercase + string.digits, k=5))
        benign_seeds_dir = Path("/tmp") / random_string / "benign"
        crash_seeds_dir = Path("/tmp") / random_string / "crash"
        benign_seeds_dir.mkdir(parents=True, exist_ok=True)
        crash_seeds_dir.mkdir(parents=True, exist_ok=True)

        post_processor = PostProcessor(
            call_graph_parser,
            scheduler,
            jazzer_json_filepath,
            available_models=["gpt-4o", "claude-3.5-sonnet"],
            shared_oss_fuzz_target=shared_oss_fuzz_target,
            benign_seeds_dir=benign_seeds_dir,
            crash_seeds_dir=crash_seeds_dir,
            harness_name=harness_name,
            harness_filepath=harness_filepath,
            oss_fuzz_target=mockcp_java_project
        )

        post_processor.process_result_queue()

        assert len(os.listdir(crash_seeds_dir)) >= 3


    @not_run_on_ci
    def test_llm_seed_gen_no_triage(self):
        target_dir = TARGET / "zip4j"
        func_index_path = target_dir / "function_indices.json"
        func_dir = target_dir / "func_json_dir"
        harness_name = "Zip4jFuzzer"
        project_id = "1"
        codeql_report = {}
        client = CodeQLClient()
        for ql_file in QUERY_PATH.iterdir():
            with open(ql_file, "r") as f:
                query = f.read()
            # FIXME: project id
            query_result = client.query({
                "cp_name": "mock-java",
                "project_id": project_id,
                "query": query
            })
            codeql_report[ql_file.stem] = query_result

        cp_root = target_dir / "zip4j-cp"
        harness_filepath = cp_root / "Zip4jFuzzer.java"
        source_root = target_dir / "zip4j-source"
        language = "java"

        # zip4j_project = setup_oss_fuzz(cp_root, source_root)

        ql_record_struct = [
            CodeQLStruct.SOURCE_NAME, CodeQLStruct.TARGET_NAME,
            CodeQLStruct.CALL_FILEPATH, CodeQLStruct.CALL_LINENO,
            CodeQLStruct.SOURCE_FILEPATH, CodeQLStruct.SOURCE_LINENO,
            CodeQLStruct.TARGET_FILEPATH, CodeQLStruct.TARGET_LINENO,
            CodeQLStruct.SANITIZER_NAME, CodeQLStruct.SINK_LOCATION
        ]
        codeql_report_parser = CodeQLReportParser(
            codeql_report,
            ql_record_struct
        )

        # program = Program(**program_info)
        call_graph_parser = CallGraphParser(
            cp_root,
            codeql_report_parser,
            language="java",
            source=['fuzzerTestOneInput'],
            source_harness_filepath=[harness_filepath],
            sink=codeql_report_parser.sanitizer_sink_functions,
            sink_type=SinkType.SANITIZER,
            function_json_dir=target_dir /  "func_json_dir",
            func_indexer=target_dir / "function_indices.json"
        )

        for node in call_graph_parser.nodes.values():
            _l.info(f"The function source code is {node.function_name}")
            _l.info(f"The function id is {node.id}")

        # This is the call path for zip4j cpv2
        dict_path = [
            {
                "function_name": "fuzzerTestOneInput",
                "filepath": "/src/Zip4jFuzzer.java"
            },
            {
                "function_name": "extractAll",
                "filepath": "/src/zip4j/src/main/java/net/lingala/zip4j/ZipFile.java",
            },
            {
                "function_name": "performTaskWithErrorHandling",
                "filepath": "/src/zip4j/src/main/java/net/lingala/zip4j/tasks/AsyncZipTask.java"
            },
            {
                "function_name": "executeTask",
                "filepath": "/src/zip4j/src/main/java/net/lingala/zip4j/tasks/ExtractAllFilesTask.java",
            },
            {
                "function_name": "extractFile",
                "filepath": "/src/zip4j/src/main/java/net/lingala/zip4j/tasks/AbstractExtractFileTask.java"
            },
            {
                "function_name": "assertCanonicalPathsAreSame",
                "filepath": "/src/zip4j/src/main/java/net/lingala/zip4j/tasks/AbstractExtractFileTask.java"
            }
        ]

        path = []
        for member in dict_path:
            for node in call_graph_parser.nodes.values():
                if node.function_name == member["function_name"] and node.filepath == Path(member["filepath"]):
                    path.append(node)
                    break
        abs_harness_filepath = harness_filepath
        model = "claude-3.5-sonnet"
        # for path in paths:
        assert len(path) == len(dict_path)
        # harness_filepath = source_node.filepath
        # _l.debug(f"harness path is {harness_filepath}")
        jazzer_json_filepath = JAZZER_SANITIZER
        
        # TODO: All the prompts generation should happen in side LLM module, we should just pass info to LLM
        with open(jazzer_json_filepath, "r") as f:
            jazzer_sanitizer_description = json.load(f)

        # This is to avoid llm api rate limit
        seed_generator_task = SeedGeneratorTask(path, jazzer_sanitizer_description, model, abs_harness_filepath, harness_name)
        agent_plan = tempfile.NamedTemporaryFile(delete=False).name
        seed_generator_processor = SeedGenerator(
            agent_plan, 
            call_graph_parser.cp_root, 
            call_graph_parser.func_indexer_path, 
            call_graph_parser.function_json_dir, 
            model
            )

        result0, result = seed_generator_processor(seed_generator_task)
        
        generated_seed_script, generated_seed = result
        _l.debug(f"generated seed is {generated_seed}")
        _l.debug(f"generated seed script is {generated_seed_script}")
        assert generated_seed
        assert generated_seed_script

    @not_run_on_ci
    def test_zip4j_cpv1_llm_seed_gen_with_triage(self):
        target_dir = TARGET / "zip4j"
        func_index_path = target_dir / "function_indices.json"
        func_dir = target_dir / "func_json_dir"
        harness_name = "Zip4jFuzzer"
        project_id = "2"
        codeql_report = {}
        client = CodeQLClient()
        for ql_file in QUERY_PATH.iterdir():
            with open(ql_file, "r") as f:
                query = f.read()
            # FIXME: project id
            query_result = client.query({
                "cp_name": "zip4j",
                "project_id": project_id,
                "query": query
            })
            codeql_report[ql_file.stem] = query_result

        cp_root = target_dir / "zip4j-cp"
        harness_filepath = cp_root / "Zip4jFuzzer.java"
        source_root = target_dir / "zip4j-source"
        language = "java"

        zip4j_project = setup_oss_fuzz_debug_build(cp_root, source_root)
        # zip4j_project = OSSFuzzProject(
        #     oss_fuzz_project_path=cp_root,
        #     project_source=source_root,
        #     use_task_service=False
        # )

        ql_record_struct = [
            CodeQLStruct.SOURCE_NAME, CodeQLStruct.TARGET_NAME,
            CodeQLStruct.CALL_FILEPATH, CodeQLStruct.CALL_LINENO,
            CodeQLStruct.SOURCE_FILEPATH, CodeQLStruct.SOURCE_LINENO,
            CodeQLStruct.TARGET_FILEPATH, CodeQLStruct.TARGET_LINENO,
            CodeQLStruct.SANITIZER_NAME, CodeQLStruct.SINK_LOCATION
        ]
        codeql_report_parser = CodeQLReportParser(
            codeql_report,
            ql_record_struct
        )

        call_graph_parser = CallGraphParser(
            cp_root,
            codeql_report_parser,
            language="java",
            source=['fuzzerTestOneInput'],
            source_harness_filepath=[harness_filepath],
            sink=codeql_report_parser.sanitizer_sink_functions,
            sink_type=SinkType.SANITIZER,
            function_json_dir=target_dir /  "func_json_dir",
            func_indexer=target_dir / "function_indices.json"
        )

        for node in call_graph_parser.nodes.values():
            _l.info(f"The function source code is {node.function_name}")
            _l.info(f"The function id is {node.id}")

        # This is the call path for zip4j cpv1
        dict_path = [
            {
                "function_name": "fuzzerTestOneInput",
                "filepath": "/src/Zip4jFuzzer.java"
            },
            {
                "function_name": "getZip64ExtendedInfo",
                "filepath": "/src/zip4j/src/main/java/net/lingala/zip4j/model/AbstractFileHeader.java",
            },
            {
                "function_name": "exec",
                "filepath": "/modules/java.base/java/lang/Runtime.class"
            },
        ]

        path = []
        for member in dict_path:
            for node in call_graph_parser.nodes.values():
                if node.function_name == member["function_name"] and node.filepath == Path(member["filepath"]):
                    path.append(node)
                    break
        abs_harness_filepath = harness_filepath
        model = "claude-3.5-sonnet"
        # for path in paths:
        assert len(path) == len(dict_path)
        # harness_filepath = source_node.filepath
        # _l.debug(f"harness path is {harness_filepath}")
        jazzer_json_filepath = JAZZER_SANITIZER

        # TODO: All the prompts generation should happen in side LLM module, we should just pass info to LLM
        with open(jazzer_json_filepath, "r") as f:
            jazzer_sanitizer_description = json.load(f)
        _l.debug(f"jazzer sanitizer {jazzer_sanitizer_description}")
        # This is to avoid llm api rate limit
        seed_generator_task = SeedGeneratorTask(path, jazzer_sanitizer_description, model, abs_harness_filepath, harness_name)
        agent_plan = tempfile.NamedTemporaryFile(delete=False).name
        seed_generator_processor = SeedGenerator(
            agent_plan, 
            call_graph_parser.cp_root, 
            call_graph_parser.func_indexer_path, 
            call_graph_parser.function_json_dir, 
            model
            )

        result0, result = seed_generator_processor(seed_generator_task)
        
        generated_seed_script, generated_seed = result
        _l.debug(f"generated seed is {generated_seed}")
        _l.debug(f"generated seed script is {generated_seed_script}")
        assert generated_seed
        assert generated_seed_script            

        crashing, msg = run_crash_input(zip4j_project, harness_name, generated_seed)
        assert crashing


    @not_run_on_ci
    def test_coverage_trace_jenkins(self):
        # To run this test,  we need a docker images that can be built by  running run_build_from_backup.sh
        # from coverage-guy and also target_built_with_coverage from backup
        # Also because now the coveragelib has bug, we need to copy function_indices.json to jenkins_src_repo/work/antlr4_index.json
        target_dir = TARGET / "jenkins"
        jenkins_src_repo = target_dir / "target_built_with_coverage"

        triage_seed_path = target_dir / "triage_seeds"
        harness_name = "JenkinsTwo"
        # producer_fuzzer_blocker = FuzzerBlockerProducer(


        coverage_analysis = CoverageAnalysis(triage_seed_path, harness_name, jenkins_src_repo, java_tracing_type="btrace")
        coverage = coverage_analysis.trace_coverage()

        _l.debug(f"The coverage is {coverage}")
        
    @not_run_on_ci
    def test_coveragelib(self):
        seeds = ["/shared/output.bin"]

        with Tracer("/shared/zip4j/", "Zip4jFuzzer", aggregate=True) as tracer:
                res = tracer.trace(*seeds)
                # dump res on file
                # open res file and copy the content in a file
                print(res)
                #shutil.copy(res[0], "./mock_java_results.txt")

    # We cannot run this on ci because we did not upload the target_built_with_coverage.tar.gz
    @not_run_on_ci
    def test_end_to_end_mock_cp_java_pd(self):
        # run_build_test("jenkins-cp")
        # specified in test-utils in libs
        target = "mock-cp-java"
        target_dir = TARGET / "mock-cp-java"
        docker_path = Path(__file__).parent.parent.resolve()
        _l.debug(f"docker path is {docker_path}")
        build_docker(docker_path, "aixcc-quickseed", build_args=["IMAGE_PREFIX=ghcr.io/shellphish-support-syndicate/"],
                     pull_component_base=False)
        # prep_target(target)
        lock_pipeline()
        # pipeline_inject("quick_seed.build_configuration:", pd_id="1",
        #                 data = b"""\
        #                     architecture: x86_64
        #                     project_id: 9fdd934f0f1c479e99ea654c16394d6b
        #                     project_name: mock-cp-java
        #                     sanitizer: address""")
        pipeline_inject("quick_seed.codeql_db_ready", pd_id="1", file=target_dir / "codeql_db_ready/9fdd934f0f1c479e99ea654c16394d6b.yaml")
        pipeline_inject("quick_seed.coverage_build_artifacts", pd_id="1", file=target_dir / "coverage_build_artifacts.tar.gz")
        pipeline_inject("quick_seed.crs_tasks_analysis_source", pd_id="1", file=target_dir / "crs_tasks_analysis_source.tar.gz")
        pipeline_inject("quick_seed.crs_tasks_oss_fuzz_repos", pd_id="1", file=target_dir / "crs_tasks_oss_fuzz_repos.tar.gz")
        pipeline_inject("quick_seed.debug_build_artifacts", pd_id="1", file=target_dir / "debug_build_artifacts.tar.gz")
        pipeline_inject("quick_seed.full_functions_index", pd_id="1", file=target_dir / "function_indices.json")
        pipeline_inject("quick_seed.full_functions_jsons_dir", pd_id="1",file=target_dir / "func_json_dir.tar.gz")
        pipeline_inject("quick_seed.full_mode_tasks", pd_id="1", data= b"""\
deadline: 1743349804000
focus: shellphish-mock-java
harnesses_included: true
metadata:
  round.id: local-dev
  task.id: 9fdd934f-0f1c-479e-99ea-654c16394d6b
  pdt_task_id: 9fdd934f0f1c479e99ea654c16394d6b
  project_name: mock-cp-java
source:
- sha256: fe2b2745fbeba64eeee73f847e5a8f4387e6e26e1e47ddb725625b2d5eb06095
  type: repo
  url: https://artiphishellci.blob.core.windows.net/targets/fe2b2745fbeba64eeee73f847e5a8f4387e6e26e1e47ddb725625b2d5eb06095.tar.gz?se=2025-03-30T15%3A50%3A03Z&sp=r&sv=2022-11-02&sr=b&sig=u9226H68yugTG9DJirdJOBhxy2vVSvQ%2FE%2FxBUqzqXgY%3D
- sha256: f37061ec88c4f00e57e07d0e4476283dcded922c6383901de987bc455a382495
  type: fuzz-tooling
  url: https://artiphishellci.blob.core.windows.net/targets/f37061ec88c4f00e57e07d0e4476283dcded922c6383901de987bc455a382495.tar.gz?se=2025-03-30T15%3A49%3A59Z&sp=r&sv=2022-11-02&sr=b&sig=BZN22CJiJeX%2FusV0zZ6WY96UwSTOTA6%2BxuJCyLUiZ5k%3D
- sha256: 2b80f77bb41e6deac26cb77c5546b96231a0b0a269f97a4430a836bd8896cc8c
  type: diff
  url: https://artiphishellci.blob.core.windows.net/targets/2b80f77bb41e6deac26cb77c5546b96231a0b0a269f97a4430a836bd8896cc8c.tar.gz?se=2025-03-30T15%3A49%3A56Z&sp=r&sv=2022-11-02&sr=b&sig=tomyZLZEXbV8DyH9kAqpEehpPCWmZr%2FNF03GRq3iado%3D
task_id: 9fdd934f-0f1c-479e-99ea-654c16394d6b
task_sanitizer: address
task_uuid: 9fdd934f-0f1c-479e-99ea-654c16394d6b
type: delta"""
                        )
        pipeline_inject("quick_seed.quickseed_codeql_report", pd_id="1", file=target_dir / "codeql_report.yaml")
        pipeline_inject("quick_seed.project_metadata", pd_id="1", data= b"""\
architectures:
- x86_64
auto_ccs: null
blackbox: false
builds_per_day: null
coverage_extra_args: null
disabled: false"""
                        )
        pipeline_inject("quick_seed.project_id", pd_id="1", file=target_dir / "project_id/9fdd934f0f1c479e99ea654c16394d6b.yaml")
        pipeline_inject("quick_seed.project_harness_infos", pd_id="1", file = target_dir / "harness_infos/harness_info_1.yaml")
        pipeline_inject("quick_seed.project_harness_infos", pd_id="1", file = target_dir / "harness_infos/harness_info_2.yaml")
        pipeline_inject("quick_seed.project_metadata_path", pd_id="1", file = target_dir / "project_metadata_path.yaml")

        pipeline_run(before_args=["--verbose", "--debug-trace"])

        logs = pipeline_list_ids("quick_seed.logs")
        output = pipeline_get_data("quick_seed.logs", logs[0]).decode('latin-1')
        status = pipeline_status("json")

        truncated_output = output.split("\n")
        _l.debug(f"output is {truncated_output}")
        _l.debug(f"status is {status}")

        success = status['quick_seed_no_coverage']['success'][0]
        assert len(success) > 0

    @not_run_on_ci
    def test_jenkins_reflection_analyzer(self):
        target_dir = TARGET / "jenkins"
        report = target_dir / "demo_codeql_report.yaml"
        cp_root = target_dir / "targets-semis-aixcc-sc-challenge-002-jenkins-cp"
        jazzer_json_filepath = JAZZER_SANITIZER

        ql_record_struct = [
            CodeQLStruct.SOURCE_NAME, CodeQLStruct.TARGET_NAME, \
            CodeQLStruct.CALL_FILEPATH, CodeQLStruct.CALL_LINENO, \
            CodeQLStruct.SOURCE_FILEPATH, CodeQLStruct.SOURCE_LINENO, \
            CodeQLStruct.TARGET_FILEPATH, CodeQLStruct.TARGET_LINENO, \
            CodeQLStruct.SANITIZER_NAME, CodeQLStruct.SINK_LOCATION
        ]
        codeql_report_parser = CodeQLReportParser(
            report,
            ql_record_struct
        )

        # program = Program(**program_info)
        call_graph_parser = CallGraphParser(
            cp_root,
            codeql_report_parser,
            language="java",
            source=['fuzzerTestOneInput'],
            sink=['ProcessBuilder'],
            sink_type=SinkType.SANITIZER,
            function_json_dir=target_dir /  "func_json_dir",
            func_indexer=target_dir / "function_indices.json"
        )

        for node in call_graph_parser.nodes.values():
            _l.info(f"The function source code is {node.function_name}")
            _l.info(f"The function id is {node.id}")

        assert len(call_graph_parser.nodes) == 7
        assert len(call_graph_parser.edges) == 8
        assert len(call_graph_parser.graph.nodes()) == 6
        assert len(call_graph_parser.graph.edges()) == 6


        other_ql_record_struct = [
            CodeQLStruct.REFLECTION_CALL_METHOD_NAME, CodeQLStruct.UNDEFINED,
            CodeQLStruct.REFLECTION_CALL_METHOD_LOCATION, CodeQLStruct.REFLECTION_CALL_LOCATION]
        codeql_report = target_dir / "incomplete_codeql_report.yaml"
        codeql_report_parser = CodeQLReportParser(codeql_report, ql_record_struct, other_ql_record_struct)
        call_graph_parser = CallGraphParser(
            cp_root,
            codeql_report_parser,
            language="java",
            source=['fuzzerTestOneInput'],
            sink=['ProcessBuilder'],
            sink_type=SinkType.SANITIZER,
            function_json_dir=target_dir /  "func_json_dir",
            func_indexer=target_dir / "function_indices.json"
        )

        reflection_parser = ReflectionParser(codeql_report_parser)

        scheduler = Scheduler()
        output_dir = Path(tempfile.mktemp(prefix="reflection_output_", dir="/tmp"))

        initializer = Initializer(scheduler, call_graph_parser, reflection_parser=reflection_parser, jazzer_json = jazzer_json_filepath, reflection_output_dir=output_dir)
        scheduler.start()
        initializer.submit_tasks_to_scheduler()
        try:
            scheduler.wait_finish()
        except KeyboardInterrupt:
            _l.info("Keyboard interrupt received, stopping the scheduler")
        
        seed_path = output_dir / "JenkinsTwo"
        assert len(list(seed_path.rglob('*')))==5

        

    # We do not have target_built_with_coverage and not docker image required to run this
    @not_run_on_ci
    def test_jenkins_reflection_analyzer_to_complete_graph(self):
        target_dir = TARGET / "jenkins"
        cp_root = target_dir / "targets-semis-aixcc-sc-challenge-002-jenkins-cp"
        jazzer_json_filepath = JAZZER_SANITIZER
        language = "java"

        ql_record_struct = [
            CodeQLStruct.SOURCE_NAME, CodeQLStruct.TARGET_NAME, \
            CodeQLStruct.CALL_FILEPATH, CodeQLStruct.CALL_LINENO, \
            CodeQLStruct.SOURCE_FILEPATH, CodeQLStruct.SOURCE_LINENO, \
            CodeQLStruct.TARGET_FILEPATH, CodeQLStruct.TARGET_LINENO, \
            CodeQLStruct.SANITIZER_NAME, CodeQLStruct.SINK_LOCATION
        ]

        other_ql_record_struct = [
            CodeQLStruct.REFLECTION_CALL_METHOD_NAME, CodeQLStruct.UNDEFINED,
            CodeQLStruct.REFLECTION_CALL_METHOD_LOCATION, CodeQLStruct.REFLECTION_CALL_LOCATION]
        codeql_report = target_dir / "incomplete_codeql_report.yaml"
        codeql_report_parser = CodeQLReportParser(codeql_report, ql_record_struct, other_ql_record_struct)
        call_graph_parser = CallGraphParser(
            cp_root,
            codeql_report_parser,
            language="java",
            source=['fuzzerTestOneInput'],
            sink=['ProcessBuilder'],
            sink_type=SinkType.SANITIZER,
            function_json_dir=target_dir /  "func_json_dir",
            func_indexer=target_dir / "function_indices.json"
        )

        reflection_parser = ReflectionParser(codeql_report_parser)

        scheduler = Scheduler()
        output_dir = Path(tempfile.mktemp(prefix="reflection_output_", dir="/tmp"))

        initializer = Initializer(scheduler, call_graph_parser, reflection_parser=reflection_parser, jazzer_json = jazzer_json_filepath, reflection_output_dir=output_dir, available_models=["gpt-4o"])
        scheduler.start()
        initializer.submit_tasks_to_scheduler()
        try:
            scheduler.wait_finish()
        except KeyboardInterrupt:
            _l.info("Keyboard interrupt received, stopping the scheduler")

        random_string = ''.join(random.choices(string.ascii_lowercase + string.digits, k=5))
        benign_seeds_dir = Path("/tmp") / random_string / "benign"
        crash_seeds_dir = Path("/tmp") / random_string / "crash"
        benign_seeds_dir.mkdir(parents=True, exist_ok=True)
        crash_seeds_dir.mkdir(parents=True, exist_ok=True)
        post_processor = PostProcessor(
            call_graph_parser,
            scheduler,
            jazzer_json_filepath,
            available_models = ["gpt-4o", "claude-3.5-sonnet"],
            target_src_with_coverage=target_dir / "target_built_with_coverage",
            benign_seeds_dir=benign_seeds_dir,
            crash_seeds_dir=crash_seeds_dir,
        )
        post_processor.process_result_queue()

    @not_run_on_ci
    def test_coverage_jacoco_parser(self):
        seeds_output_dir = TARGET / "jenkins" / "reflection_inputs"
        harness_name = "JenkinsTwo"
        target_src_with_coverage = TARGET / "jenkins" / "target_built_with_coverage"

        target_dir = TARGET / "jenkins"
        cp_root = target_dir / "targets-semis-aixcc-sc-challenge-002-jenkins-cp"
        jazzer_json_filepath = JAZZER_SANITIZER
        language = "java"

        ql_record_struct = [
            CodeQLStruct.SOURCE_NAME, CodeQLStruct.TARGET_NAME, \
            CodeQLStruct.CALL_FILEPATH, CodeQLStruct.CALL_LINENO, \
            CodeQLStruct.SOURCE_FILEPATH, CodeQLStruct.SOURCE_LINENO, \
            CodeQLStruct.TARGET_FILEPATH, CodeQLStruct.TARGET_LINENO, \
            CodeQLStruct.SANITIZER_NAME, CodeQLStruct.SINK_LOCATION
        ]

        other_ql_record_struct = [
            CodeQLStruct.REFLECTION_CALL_METHOD_NAME, CodeQLStruct.UNDEFINED,
            CodeQLStruct.REFLECTION_CALL_METHOD_LOCATION, CodeQLStruct.REFLECTION_CALL_LOCATION]
        codeql_report = target_dir / "incomplete_codeql_report.yaml"
        codeql_report_parser = CodeQLReportParser(codeql_report, ql_record_struct, other_ql_record_struct)
        call_graph_parser = CallGraphParser(
            cp_root,
            codeql_report_parser,
            language="java",
            source=['fuzzerTestOneInput'],
            sink=['ProcessBuilder'],
            sink_type=SinkType.SANITIZER,
            function_json_dir=target_dir /  "func_json_dir",
            func_indexer=target_dir / "function_indices.json"
        )
        original_edge_num = len(call_graph_parser.graph.edges)
        source_id = None
        second_id = None
        for id, node in call_graph_parser.nodes.items():
            if node.function_name == "fuzzerTestOneInput":
                source_id = id
            if node.function_name == "fuzz":
                second_id = id
        assert source_id
        assert second_id
        query_paths = [[source_id, second_id]]
        coverage_analysis = CoverageAnalysis(seeds_output_dir, harness_name, target_src_with_coverage, java_tracing_type="btrace")
        coverage = coverage_analysis.trace_coverage()
        coverage_analysis.parse_btrace_results_to_complete_graph(call_graph_parser, query_paths)

        updated_edge_num = len(call_graph_parser.graph.edges)
        assert updated_edge_num == original_edge_num + 5

    @not_run_on_ci
    def test_blocker_agent(self):
        target_dir = TARGET / "mock-cp-java"
        func_index_path = target_dir / "function_indices.json"
        func_dir = target_dir / "func_json_dir"
        harness_name = "Harness"
        project_id = "1"
        codeql_report = {}
        jazzer_json_filepath = JAZZER_SANITIZER
        client = CodeQLClient()
        for ql_file in QUERY_PATH.iterdir():
            with open(ql_file, "r") as f:
                query = f.read()
            # FIXME: project id
            query_result = client.query({
                "cp_name": "mock-cp-java",
                "project_id": project_id,
                "query": query
            })
            codeql_report[ql_file.stem] = query_result

        cp_root = target_dir / "mock-cp-java"
        harness_filepath = cp_root / "Harness.java"
        source_root = target_dir / "mock-cp-java-source"
        language = "java"

        # mockckp_java_project = setup_oss_fuzz(cp_root, source_root)

        ql_record_struct = [
            CodeQLStruct.SOURCE_NAME, CodeQLStruct.TARGET_NAME,
            CodeQLStruct.CALL_FILEPATH, CodeQLStruct.CALL_LINENO,
            CodeQLStruct.SOURCE_FILEPATH, CodeQLStruct.SOURCE_LINENO,
            CodeQLStruct.TARGET_FILEPATH, CodeQLStruct.TARGET_LINENO,
            CodeQLStruct.SANITIZER_NAME, CodeQLStruct.SINK_LOCATION
        ]
        codeql_report_parser = CodeQLReportParser(
            codeql_report,
            ql_record_struct
        )

        # program = Program(**program_info)
        call_graph_parser = CallGraphParser(
            cp_root,
            codeql_report_parser,
            language="java",
            source=['fuzzerTestOneInput'],
            source_harness_filepath=[harness_filepath],
            sink=codeql_report_parser.sanitizer_sink_functions,
            sink_type=SinkType.SANITIZER,
            function_json_dir=target_dir /  "func_json_dir",
            func_indexer=target_dir / "function_indices.json"
        )

        # target_dir = TARGET / "jenkins"
        # cp_root = target_dir / "targets-semis-aixcc-sc-challenge-002-jenkins-cp"
        # jazzer_json_filepath = JAZZER_SANITIZER
        # language = "java"

        # ql_record_struct = [
        #     CodeQLStruct.SOURCE_NAME, CodeQLStruct.TARGET_NAME, \
        #     CodeQLStruct.CALL_FILEPATH, CodeQLStruct.CALL_LINENO, \
        #     CodeQLStruct.SOURCE_FILEPATH, CodeQLStruct.SOURCE_LINENO, \
        #     CodeQLStruct.TARGET_FILEPATH, CodeQLStruct.TARGET_LINENO, \
        #     CodeQLStruct.SANITIZER_NAME, CodeQLStruct.SINK_LOCATION
        # ]

        # other_ql_record_struct = [
        #     CodeQLStruct.REFLECTION_CALL_METHOD_NAME, CodeQLStruct.UNDEFINED,
        #     CodeQLStruct.REFLECTION_CALL_METHOD_LOCATION, CodeQLStruct.REFLECTION_CALL_LOCATION]
        # codeql_report = target_dir / "incomplete_codeql_report.yaml"
        # codeql_report_parser = CodeQLReportParser(codeql_report, ql_record_struct, other_ql_record_struct)
        # call_graph_parser = CallGraphParser(
        #     cp_root,
        #     codeql_report_parser,
        #     language="java",
        #     source=['fuzzerTestOneInput'],
        #     sink=['ProcessBuilder'],
        #     sink_type=SinkType.SANITIZER,
        #     function_json_dir=target_dir /  "func_json_dir",
        #     func_indexer=target_dir / "function_indices.json"
        # )

        # set environment variable USE_LLM_API, AIXCC_LITELLM_HOSTNAME, LITELLM_KEY when local testing
        node_name_path = ["fuzzerTestOneInput", "execThirtyFiveUtils", "createUtils"]
        node_path = []
        for name in node_name_path:
            for node in call_graph_parser.nodes.values():
                if node.function_name == name:
                    node_path.append(node)
                    break
        
        llm_generated = target_dir / "llm_generated"
        seed_gen_scripts = Path(llm_generated) / "gen_seed.py"
        generated_seed = Path(llm_generated) / "output.bin"
        stuck_method_index = 1
        no_harness_path = call_graph_parser.cut_harness_from_path(node_path)
        source_code = ""
        count = 1
        for node in no_harness_path:
            source_code += f"{count}. {node.function_name}\n"
            count += 1
            if node.function_code is not None:
                source_code += f"{node.function_code}\n"

        model = "gpt-4o"
        blocker_analyzer_task = BlockerAnalyzerTask(
            node_path=node_path,
            stuck_method_index=stuck_method_index,
            harness_name=harness_name,
            harness_filepath=harness_filepath,
            script_path=seed_gen_scripts,
            source_code=source_code,
            model = model                 
        )
        agent_plan = tempfile.NamedTemporaryFile(delete=False).name
        blocker_analyzer = BlockerAnalyzer(
            agent_plan, 
            call_graph_parser.cp_root, 
            call_graph_parser.func_indexer_path, 
            call_graph_parser.function_json_dir, 
            model
        )
        blocker_analyzer(blocker_analyzer_task)

    @not_run_on_ci
    def test_codeql_client(self):
        # Preparation:
        # Under services/codeql_server: docker compose up
        # Under libs/libcodeql: CODEQL_SERVER_URL='http://localhost:4000' codeql-upload-db  \
        # --cp_name zip4j --project_id 1 --language java --db_file <codeql_db_filepath>
        project_id = "1"
        codeql_report = {}
        client = CodeQLClient()
        for ql_file in QUERY_PATH.iterdir():
            with open(ql_file, "r") as f:
                query = f.read()
            # FIXME: project id
            query_result = client.query({
                "cp_name": "zip4j",
                "project_id": project_id,
                "query": query
            })
            codeql_report[ql_file.stem] = query_result
            assert codeql_report["CommandInjection"]

    @not_run_on_ci
    def test_crs_utils_run_pov(self):
        target_dir = TARGET / "tika"
        cp_root = target_dir / "tika"
        harness_filepath = cp_root / "harnesses/Fuzzer.java"
        source_root = target_dir / "tika-source"
        # source_root = Path("shared/mock-cp-java-source")
        language = "java"
        harness_name = "Fuzzer"
        shared_oss_fuzz_target = "/shared/mock-cp-java"
        # setup_coverage_target(shared_oss_fuzz_target, source_root)
        mockcp_java_project = setup_oss_fuzz_debug_build(cp_root, source_root)

        seed = Path("/home/siyu/aixcc/artiphishell-ossfuzz-meta/tika/cpv_info/cpv1/crashing_inp")
        crashed, _ = run_crash_input(mockcp_java_project, harness_name, seed)
        assert crashed

    @not_run_on_ci
    def test_tika_call_graph_parser(self):
        target_dir = TARGET / "tika"
        func_index_path = target_dir / "function_indices.json"
        func_dir = target_dir / "func_json_dir"
        harness_name = "Fuzzer"
        project_id = "2"
        codeql_report = {}
        client = CodeQLClient()
        _l.debug(f"start query the codeql database ...")
        for ql_file in QUERY_PATH.iterdir():
            if  "ReflectionCall" in str(ql_file):
                continue
            with open(ql_file, "r") as f:
                query = f.read()
            # FIXME: project id
            query_result = client.query({
                "cp_name": "tika",
                "project_id": project_id,
                "query": query
            })
            codeql_report[ql_file.stem] = query_result

        _l.debug(f"Done querying the codeql database")
        cp_root = target_dir / "tika"
        harness_filepath = cp_root / "harnesses/Fuzzer.java"
        source_root = target_dir / "tika-source"
        language = "java"


        # zip4j_project = setup_oss_fuzz(cp_root, source_root)

        ql_record_struct = [
            CodeQLStruct.SOURCE_QUALIFIED_NAME, CodeQLStruct.TARGET_QUALIFIED_NAME,
            CodeQLStruct.CALL_FILEPATH, CodeQLStruct.CALL_LINENO,
            CodeQLStruct.SOURCE_FILEPATH, CodeQLStruct.SOURCE_LINENO,
            CodeQLStruct.TARGET_FILEPATH, CodeQLStruct.TARGET_LINENO,
            CodeQLStruct.SANITIZER_NAME, CodeQLStruct.SINK_QUALIFIED_NAME
        ]
        other_ql_record_struct = {
            # "ReflectionCall": 
            # [
            #     CodeQLStruct.REFLECTION_CALL_METHOD_NAME, CodeQLStruct.UNDEFINED,
            #     CodeQLStruct.REFLECTION_CALL_METHOD_LOCATION, CodeQLStruct.REFLECTION_CALL_LOCATION
            # ],
            "AbstractOverride":
            [
                CodeQLStruct.SOURCE_NAME, CodeQLStruct.SOURCE_LOCATION,
                CodeQLStruct.TARGET_NAME, CodeQLStruct.TARGET_LOCATION
            ]
        }
        _l.debug(f"Starting the report parser")
        # codeql_report_parser = CodeQLReportParser(
        #     codeql_report,
        #     ql_record_struct,
        #     other_ql_record_struct
        # )
        with open("report_parser.pkl", "rb") as f:
            codeql_report_parser = pickle.load(f)

        _l.debug(f"starting the call graph parser ")
        # program = Program(**program_info)
        call_graph_parser = CallGraphParser(
            cp_root,
            codeql_report_parser,
            language="java",
            source=['fuzzerTestOneInput'],
            source_harness_filepath=[harness_filepath],
            sink=codeql_report_parser.sanitizer_sink_functions,
            sink_type=SinkType.SANITIZER,
            function_json_dir=target_dir /  "func_json_dir",
            func_indexer=target_dir / "function_indices.json",
            codeql_client=client,
            project_id=project_id,
            source_root=source_root
        )



        # for node in call_graph_parser.nodes.values():
        #     _l.info(f"The function source code is {node.function_name}")
        #     _l.info(f"The function id is {node.id}")
        # with open("call_graph_parser_tika.pkl", "rb") as f:
        #     call_graph_parser = pickle.load(f)


    @not_run_on_ci
    def test_tika_command_injection_cpv1_seed_gen(self):
        partial_path = [{
            "function_name": "startElement",
            "filepath": "HtmlHandler.java",
        },
        {
            "function_name": "handleDataURIScheme",
            "filepath": "HtmlHandler.java",
        },
        {
            "function_name": "parseEmbedded",
            "filepath": "EmbeddedDocumentExtractor.java",
        },
        {
            "function_name": "parseEmbedded",
            "filepath": "ParsingEmbeddedDocumentExtractor.java",
        },
        {
            "function_name": "parse",
            "filepath": "Parser.java",
        },
        {
            "function_name": "parse",
            "filepath": "ExternalParser.java",
        },
        {
            "function_name": "exec",
            "filepath": "Runtime.class",
        }
        ]
        target_dir = TARGET / "tika"
        func_index_path = target_dir / "function_indices.json"
        func_dir = target_dir / "func_json_dir"
        harness_name = "Fuzzer"
        project_id = "2"
        codeql_report = {}
        client = CodeQLClient()
        _l.debug(f"start query the codeql database ...")
        # for ql_file in QUERY_PATH.iterdir():
        #     if "FileSystem" in str(ql_file) or "ReflectionCall" in str(ql_file):
        #         continue
        #     with open(ql_file, "r") as f:
        #         query = f.read()
        #     # FIXME: project id
        #     query_result = client.query({
        #         "cp_name": "tika",
        #         "project_id": project_id,
        #         "query": query
        #     })
        #     codeql_report[ql_file.stem] = query_result

        _l.debug(f"Done querying the codeql database")
        cp_root = target_dir / "tika"
        harness_filepath = cp_root / "harnesses/Fuzzer.java"
        source_root = target_dir / "tika-source"
        language = "java"

        # zip4j_project = setup_oss_fuzz(cp_root, source_root)

        ql_record_struct = [
            CodeQLStruct.SOURCE_NAME, CodeQLStruct.TARGET_NAME,
            CodeQLStruct.CALL_FILEPATH, CodeQLStruct.CALL_LINENO,
            CodeQLStruct.SOURCE_FILEPATH, CodeQLStruct.SOURCE_LINENO,
            CodeQLStruct.TARGET_FILEPATH, CodeQLStruct.TARGET_LINENO,
            CodeQLStruct.SANITIZER_NAME, CodeQLStruct.SINK_LOCATION
        ]
        other_ql_record_struct = {
            # "ReflectionCall": 
            # [
            #     CodeQLStruct.REFLECTION_CALL_METHOD_NAME, CodeQLStruct.UNDEFINED,
            #     CodeQLStruct.REFLECTION_CALL_METHOD_LOCATION, CodeQLStruct.REFLECTION_CALL_LOCATION
            # ],
            "AbstractOverride":
            [
                CodeQLStruct.SOURCE_NAME, CodeQLStruct.SOURCE_LOCATION,
                CodeQLStruct.TARGET_NAME, CodeQLStruct.TARGET_LOCATION
            ]
        }
        _l.debug(f"Starting the report parser")
        codeql_report_parser = CodeQLReportParser(
            codeql_report,
            ql_record_struct,
            other_ql_record_struct
        )


        _l.debug(f"starting the call graph parser ")
        # program = Program(**program_info)
        call_graph_parser = CallGraphParser(
            cp_root,
            codeql_report_parser,
            language="java",
            source=['fuzzerTestOneInput'],
            source_harness_filepath=[harness_filepath],
            sink=codeql_report_parser.sanitizer_sink_functions,
            sink_type=SinkType.SANITIZER,
            function_json_dir=target_dir /  "func_json_dir",
            func_indexer=target_dir / "function_indices.json"
        )


        for node in call_graph_parser.nodes.values():
            _l.info(f"The function source code is {node.function_name}")
            _l.info(f"The function id is {node.id}")

        
        path = []
        for member in partial_path:
            for node in call_graph_parser.nodes.values():
                if node.function_name == member["function_name"] and member["filepath"] in str(node.filepath):
                    path.append(node)
                    break
        call_graph_parser.code_parse_for_nodes(path)
        abs_harness_filepath = harness_filepath
        model = "claude-3.5-sonnet"
        # for path in paths:
        assert len(path) == len(partial_path)
        # harness_filepath = source_node.filepath
        # _l.debug(f"harness path is {harness_filepath}")
        jazzer_json_filepath = JAZZER_SANITIZER
        
        # TODO: All the prompts generation should happen in side LLM module, we should just pass info to LLM
        with open(jazzer_json_filepath, "r") as f:
            jazzer_sanitizer_description = json.load(f)
        _l.debug(f"jazzer sanitizer {jazzer_sanitizer_description}")
        # This is to avoid llm api rate limit
        seed_generator_task = SeedGeneratorTask(path, jazzer_sanitizer_description, model, abs_harness_filepath, harness_name)
        agent_plan = tempfile.NamedTemporaryFile(delete=False).name
        seed_generator_processor = SeedGenerator(
            agent_plan, 
            call_graph_parser.cp_root, 
            call_graph_parser.func_indexer_path, 
            call_graph_parser.function_json_dir, 
            model
            )

        result0, result = seed_generator_processor(seed_generator_task)
        
        generated_seed_script, generated_seed = result
        assert generated_seed

    @not_run_on_ci
    def test_tika_cpv1_seed_gen(self):
        target_dir = TARGET / "tika"
        func_index_path = target_dir / "function_indices.json"
        func_dir = target_dir / "func_json_dir"
        harness_name = "Fuzzer"
        project_id = "2"
        codeql_report = {}
        jazzer_json_filepath = JAZZER_SANITIZER
        client = CodeQLClient()
        _l.debug(f"start query the codeql database ...")
        # for ql_file in QUERY_PATH.iterdir():
        #     # if "FileSystem" in str(ql_file) or "ReflectionCall" in str(ql_file):
        #     #     continue
        #     with open(ql_file, "r") as f:
        #         query = f.read()
        #     # FIXME: project id
        #     query_result = client.query({
        #         "cp_name": "tika",
        #         "project_id": project_id,
        #         "query": query
        #     })
        #     codeql_report[ql_file.stem] = query_result

        _l.debug(f"Done querying the codeql database")
        cp_root = target_dir / "tika"
        harness_filepath = cp_root / "harnesses/Fuzzer.java"
        source_root = target_dir / "tika-source"
        language = "java"

        # tika_project = setup_oss_fuzz(cp_root, source_root)

        # ql_record_struct = [
        #     CodeQLStruct.SOURCE_QUALIFIED_NAME, CodeQLStruct.TARGET_QUALIFIED_NAME,
        #     CodeQLStruct.CALL_FILEPATH, CodeQLStruct.CALL_LINENO,
        #     CodeQLStruct.SOURCE_FILEPATH, CodeQLStruct.SOURCE_LINENO,
        #     CodeQLStruct.TARGET_FILEPATH, CodeQLStruct.TARGET_LINENO,
        #     CodeQLStruct.SANITIZER_NAME, CodeQLStruct.SINK_QUALIFIED_NAME
        # ]
        # other_ql_record_struct = {
        #     "ReflectionCall": 
        #     [
        #         CodeQLStruct.REFLECTION_CALL_METHOD_NAME, CodeQLStruct.UNDEFINED,
        #          CodeQLStruct.REFLECTION_CALL_METHOD_LOCATION, CodeQLStruct.REFLECTION_CALL_LOCATION
        #     ],
        #     "AbstractOverride":
        #     [
        #         CodeQLStruct.SOURCE_NAME, CodeQLStruct.SOURCE_LOCATION,
        #         CodeQLStruct.TARGET_NAME, CodeQLStruct.TARGET_LOCATION
        #     ]
        # }
        # _l.debug(f"Starting the report parser")
        # codeql_report_parser = CodeQLReportParser(
        #     codeql_report,
        #     ql_record_struct,
        #     other_ql_record_struct
        # )
        with open("report_parser.pkl", "rb") as f:
            codeql_report_parser = pickle.load(f)

        _l.debug(f"starting the call graph parser ")
        # program = Program(**program_info)
        call_graph_parser = CallGraphParser(
            cp_root,
            codeql_report_parser,
            language="java",
            source=['fuzzerTestOneInput'],
            source_harness_filepath=[harness_filepath],
            sink=codeql_report_parser.sanitizer_sink_functions,
            sink_type=SinkType.SANITIZER,
            function_json_dir=target_dir /  "func_json_dir",
            func_indexer=target_dir / "function_indices.json", 
            codeql_client=client,
            project_id="2",
            source_root=source_root
        )
        # with open("call_graph_parser_tika.pkl", "rb") as f:
        #     call_graph_parser = pickle.load(f)


        scheduler = Scheduler(max_workers=2)

        initializer = Initializer(
            scheduler, 
            call_graph_parser, 
            reflection_parser="whatever", 
            jazzer_json = jazzer_json_filepath,
            harness_name=harness_name,
            harness_path = harness_filepath,
            available_models=["claude-3.7-sonnet", "gpt-4o"],
            )
        scheduler.start()
        initializer.submit_tasks_to_scheduler()

        scheduler.wait_finish()

    @not_run_on_ci
    def test_tika_cpv1_blocker(self):

        partial_path = [{
            "function_name": "startElement",
            "filepath": "HtmlHandler.java",
        },
        {
            "function_name": "handleDataURIScheme",
            "filepath": "HtmlHandler.java",
        },
        {
            "function_name": "parseEmbedded",
            "filepath": "EmbeddedDocumentExtractor.java",
        },
        {
            "function_name": "parseEmbedded",
            "filepath": "ParsingEmbeddedDocumentExtractor.java",
        },
        {
            "function_name": "parse",
            "filepath": "Parser.java",
        },
        {
            "function_name": "parse",
            "filepath": "ExternalParser.java",
        },
        {
            "function_name": "exec",
            "filepath": "Runtime.class",
        }
        ]
        target_dir = TARGET / "tika"
        func_index_path = target_dir / "function_indices.json"
        func_dir = target_dir / "func_json_dir"
        harness_name = "Fuzzer"
        project_id = "2"
        codeql_report = {}
        client = CodeQLClient()
        _l.debug(f"start query the codeql database ...")
        for ql_file in QUERY_PATH.iterdir():
            if "FileSystem" in str(ql_file) or "ReflectionCall" in str(ql_file):
                continue
            with open(ql_file, "r") as f:
                query = f.read()
            # FIXME: project id
            query_result = client.query({
                "cp_name": "tika",
                "project_id": project_id,
                "query": query
            })
            codeql_report[ql_file.stem] = query_result

        _l.debug(f"Done querying the codeql database")
        cp_root = target_dir / "tika"
        harness_filepath = cp_root / "harnesses/Fuzzer.java"
        source_root = target_dir / "tika-source"
        language = "java"

        # zip4j_project = setup_oss_fuzz(cp_root, source_root)

        ql_record_struct = [
            CodeQLStruct.SOURCE_NAME, CodeQLStruct.TARGET_NAME,
            CodeQLStruct.CALL_FILEPATH, CodeQLStruct.CALL_LINENO,
            CodeQLStruct.SOURCE_FILEPATH, CodeQLStruct.SOURCE_LINENO,
            CodeQLStruct.TARGET_FILEPATH, CodeQLStruct.TARGET_LINENO,
            CodeQLStruct.SANITIZER_NAME, CodeQLStruct.SINK_LOCATION
        ]
        other_ql_record_struct = {
            # "ReflectionCall": 
            # [
            #     CodeQLStruct.REFLECTION_CALL_METHOD_NAME, CodeQLStruct.UNDEFINED,
            #     CodeQLStruct.REFLECTION_CALL_METHOD_LOCATION, CodeQLStruct.REFLECTION_CALL_LOCATION
            # ],
            "AbstractOverride":
            [
                CodeQLStruct.SOURCE_NAME, CodeQLStruct.SOURCE_LOCATION,
                CodeQLStruct.TARGET_NAME, CodeQLStruct.TARGET_LOCATION
            ]
        }
        _l.debug(f"Starting the report parser")
        codeql_report_parser = CodeQLReportParser(
            codeql_report,
            ql_record_struct,
            other_ql_record_struct
        )


        _l.debug(f"starting the call graph parser ")

        call_graph_parser = CallGraphParser(
            cp_root,
            codeql_report_parser,
            language="java",
            source=['fuzzerTestOneInput'],
            source_harness_filepath=[harness_filepath],
            sink=codeql_report_parser.sanitizer_sink_functions,
            sink_type=SinkType.SANITIZER,
            function_json_dir=target_dir /  "func_json_dir",
            func_indexer=target_dir / "function_indices.json"
        )


        for node in call_graph_parser.nodes.values():
            _l.info(f"The function source code is {node.function_name}")
            _l.info(f"The function id is {node.id}")

        
        path = []
        for member in partial_path:
            for node in call_graph_parser.nodes.values():
                if node.function_name == member["function_name"] and member["filepath"] in str(node.filepath):
                    path.append(node)
                    break
        call_graph_parser.code_parse_for_nodes(path)
        abs_harness_filepath = harness_filepath
        model = "claude-3.5-sonnet"

        llm_generated = target_dir / "llm_generated"
        seed_gen_scripts = Path(llm_generated) / "gen_seed.py"
        generated_seed = Path(llm_generated) / "output.bin"
        stuck_method_index = 1
        no_harness_path = call_graph_parser.cut_harness_from_path(path)

        source_code = ""
        count = 1
        for node in no_harness_path:
            source_code += f"{count}. {node.function_name}\n"
            count += 1
            if node.function_code is not None:
                source_code += f"{node.function_code}\n"

        model = "claude-3.5-sonnet"
        blocker_analyzer_task = BlockerAnalyzerTask(
            node_path=path,
            stuck_method_index=stuck_method_index,
            harness_name=harness_name,
            harness_filepath=harness_filepath,
            script_path=seed_gen_scripts,
            source_code=source_code,
            model = model                 
        )
        agent_plan = tempfile.NamedTemporaryFile(delete=False).name
        blocker_analyzer = BlockerAnalyzer(
            agent_plan, 
            call_graph_parser.cp_root, 
            call_graph_parser.func_indexer_path, 
            call_graph_parser.function_json_dir, 
            model
        )
        blocker_analyzer(blocker_analyzer_task)

    @not_run_on_ci
    def test_parse_local_data_flow_result(self):
        with open(QUERY_TEMPLATES_PATH / "LocalDataFlow.ql.j2", "r") as f:
            query_template = f.read()
        function_name = "exec"
        client = CodeQLClient()
        project_name = "tika"
        project_id = "2"
        query_template = Template(query_template)
        query = query_template.render(function_name=function_name)

        query_result = client.query({
            "cp_name": project_name,
            "project_id": project_id,
            "query": query
        })
        result = {"LocalDataFlow": query_result}
        codeql_construct = [CodeQLStruct.SOURCE_LOCATION, CodeQLStruct.TARGET_NAME, CodeQLStruct.TARGET_CLASS_NAME]
        local_report_parser = CodeQLReportParser(result, codeql_construct)


        ldf_nodes = local_report_parser._sanitizer_nodes
        class_function_names = defaultdict(str)
        for node in ldf_nodes:
            function_name = node.get("function_name")
            class_name = node.get("class_name")
            if function_name and class_name:
                if class_name in class_function_names:
                    class_function_names[class_name].append(function_name)
                else:
                    class_function_names[class_name] = [function_name]


        potential_functions_modifying_data_flow_points = []
        for class_name, function_names in class_function_names.items():
            with open(QUERY_TEMPLATES_PATH / "FieldAccess.ql.j2", "r") as f:
                query_template = f.read()
            class_name_parts = class_name.split(".")
            class_name_prefix = ".".join(class_name_parts[:-1])
            class_name_suffix = class_name_parts[-1]
            query_template = Template(query_template)
            query = query_template.render(
                class_name_prefix = class_name_prefix, 
                class_name=class_name_suffix, 
                target_functions=function_names,
                enumerate = enumerate,
                )

            query_result = client.query({
                "cp_name": project_name,
                "project_id": project_id,
                "query": query
            })
            field_access_query_result = {"FieldAccess": query_result}
            codeql_struct = [CodeQLStruct.SOURCE_NAME, CodeQLStruct.SOURCE_CLASS_NAME, CodeQLStruct.TARGET_LOCATION]
            field_access_result_parser = CodeQLReportParser(field_access_query_result, codeql_struct)
            field_access_nodes = field_access_result_parser._sanitizer_nodes
            field_access_edges = field_access_result_parser._sanitizer_edges
            

            for i, data_flow_node in enumerate(ldf_nodes):
                if data_flow_node.get("location"):
                    for j, field_access_node in enumerate(field_access_nodes):

                        # If the dataflow points overlaps with the field access points
                        # Find the corresponding assign method
                        if field_access_node.get("filepath") == data_flow_node.get("filepath") and \
                        field_access_node.get("startline") == data_flow_node.get("startline"):
                            for edge in field_access_edges:
                                if edge.get("target_node_index") == j:

                                    source_node_index = edge.get("source_node_index")
                                    function_name = field_access_nodes[source_node_index].get("function_name")
                                    class_name = field_access_nodes[source_node_index].get("class_name")
                                    class_function_tuples = (class_name, function_name)
                                    if function_name != "<obinit>" and function_name != "<clinit>" \
                                        and class_function_tuples not in potential_functions_modifying_data_flow_points:
                                        potential_functions_modifying_data_flow_points.append(class_function_tuples)

        methods_having_data_flow_to_sink = defaultdict(tuple)
        for class_function in potential_functions_modifying_data_flow_points:
            
            full_class_name, function = class_function
            codeql_struct = [CodeQLStruct.SOURCE_NAME, CodeQLStruct.SOURCE_LOCATION, CodeQLStruct.SOURCE_CLASS_NAME]
            
            with open(QUERY_TEMPLATES_PATH / "MethodAccess.ql.j2", "r") as f:
                query_template = f.read()
            class_name_parts = full_class_name.split(".")
            class_name_prefix = ".".join(class_name_parts[:-1])
            class_name_suffix = class_name_parts[-1]
            query_template = Template(query_template)
            query = query_template.render(
                class_name_prefix=class_name_prefix,
                class_name=class_name_suffix,
                function_name=function
            )

            query_result = client.query({
                "cp_name": project_name,
                "project_id": project_id,
                "query": query
            })
            method_access_result = {"MethodAccess": query_result}

            method_access_parser = CodeQLReportParser(method_access_result, codeql_struct)

            methods_having_data_flow_to_sink[class_function] = method_access_parser._sanitizer_nodes

        assert ("org.apache.tika.parser.external.ExternalParser", "setCommand") in methods_having_data_flow_to_sink
        assert len(methods_having_data_flow_to_sink[("org.apache.tika.parser.external.ExternalParser", "setCommand")]) > 0

    @not_run_on_ci
    def test_sink_identifier_agent(self):
        target_dir = TARGET / "tika"
        func_index_path = target_dir / "function_indices.json"
        func_dir = target_dir / "func_json_dir"
        harness_name = "Fuzzer"


        cp_root = target_dir / "tika"


        client = CodeQLClient()
        project_name = "tika"
        project_id = "2"
        with open(QUERY_PATH / "MethodsFromSource.ql", "r") as f:
            query = f.read()

        query_result = client.query({
            "cp_name": project_name,
            "project_id": project_id,
            "query": query
        })

        all_methods = []
        for method_dict in query_result:
            full_method_name  = method_dict.get("col0").split(".")
            method_name = ".".join(full_method_name[-2:])
            if "Test" not in full_method_name[-2]:
                all_methods.append(method_name)
            
        agent_plan = tempfile.NamedTemporaryFile(delete=False).name
        sink_identifier = SinkIdentifier(agent_plan, cp_root, func_index_path, func_dir, model="claude-3.7-sonnet")
        sink_identifier_task = SinkIdentifierTask(all_methods)
        task, result = sink_identifier(sink_identifier_task)



        with open(QUERY_TEMPLATES_PATH / "LLMSinks.ql.j2", "r") as f:
            query_template = f.read()
        query_template = Template(query_template)
        query = query_template.render(
            target_functions=result,
            enumerate = enumerate,
        )
        query_result = client.query({
            "cp_name": project_name,
            "project_id": project_id,
            "query": query
        })

        query_result = {"LLMSinks": query_result}
        
        codeql_struct = [
            CodeQLStruct.SOURCE_QUALIFIED_NAME, CodeQLStruct.TARGET_QUALIFIED_NAME,
            CodeQLStruct.CALL_FILEPATH, CodeQLStruct.CALL_LINENO,
            CodeQLStruct.SOURCE_FILEPATH, CodeQLStruct.SOURCE_LINENO,
            CodeQLStruct.TARGET_FILEPATH, CodeQLStruct.TARGET_LINENO,
            CodeQLStruct.SANITIZER_NAME, CodeQLStruct.SINK_QUALIFIED_NAME
        ]
        llm_result_parser = CodeQLReportParser(query_result, codeql_struct)
        nodes_from_llm_sinks = llm_result_parser.sanitizer_nodes
        edges_from_llm_sinks = llm_result_parser.sanitizer_edges
