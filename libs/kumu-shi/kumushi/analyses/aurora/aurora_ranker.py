from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from analysis_graph.models.harness_inputs import HarnessInputNode
from kumushi.aixcc import AICCProgram
from neomodel import db
from kumushi.data import PoI, ProgramInput, ProgramInputType
from kumushi.tracing.flexible_tracer import FlexibleTracer

from pathlib import Path
import os
import time
import tempfile
import logging

_l = logging.getLogger(__name__)

EXPECTED_BENIGN_INPUTS_NUM = 500
EXPECTED_CRASHING_INPUTS_NUM = 200  # used to 200

# EXPECTED_BENIGN_INPUTS_NUM = 50
# EXPECTED_CRASHING_INPUTS_NUM = 20


class AuroraRanker:
    def __init__(self, program: AICCProgram, coverage_build_project_path: Path = None, aflpp_build_project_path: Path = None,
                 fuzz_engine: str = "", sanitizer: str = "", crashing_input: Path = None,
                 crashing_input_dir: Path = None,
                 fuzzing_time: int = 180, harness_info: str = None,
                 harness_name: str = None, debug_build_project_path: Path = None, debug_project: OSSFuzzProject = None):
        self.coverage_build_project_path = coverage_build_project_path
        self.debug_build_project_path = debug_build_project_path
        self.debug_project = debug_project
        self.aflpp_build_project_path = aflpp_build_project_path
        self.fuzz_engine = fuzz_engine
        self.sanitizer = sanitizer
        self.crashing_input = Path(crashing_input) if crashing_input else None
        self.crashing_input_dir = Path(crashing_input_dir) if crashing_input_dir else None
        self.program = program
        assert self.crashing_input or self.crashing_input_dir, "at least one of --crashing-input or --crashing-input-dir must be provided"
        self.fuzzing_time = fuzzing_time
        assert (harness_info) or harness_name, "either --harness-info or --function-resolver and --harness-name must be provided"
        self.harness_name = harness_name

        self.have_seen_dict = {}



    def resolve_covered_functions(
            self,
            func_names: list[str] | set[str],
    ):
        """
        Resolve covered function keys from JSON strings using the function resolver.

        Parameters:
        - covered_funcs_all_seeds: list[list[str]], where each str is a JSON object

        Returns:
        - covered_func_keys_all_seeds: list[list[func_key]]
        """
        covered_func_keys_all_seeds = []

        for func_name in func_names:
            funcs = self.program.code.functions_by_name(func_name, focus_repo_only=True)
            if funcs:
                covered_func_keys_all_seeds.append(funcs[0].function_index)
        return covered_func_keys_all_seeds

    def rank(self):
        # Get the covered functions of the benign inputs
        all_benign_num = 0
        tmp_func_in_benign_input_to_num = {}
        func_in_benign_input_to_num = {}
        benign_harness_inputs_no_coverage = []
        benign_harness_inputs = []
        for i in range(0, 3):
            benign_harness_inputs = HarnessInputNode.nodes.filter(
                crashing=False,
                harness_name=self.harness_name,
                pdt_project_id=self.program.poi_report.project_id
            ).all()
            if len(benign_harness_inputs) > 0:
                break
            else:
                _l.info("No benign harness inputs found, retrying...")
                time.sleep(5)
                continue
        for harness_input in benign_harness_inputs:
            # covered_functions = len(harness_input.covered_functions)
            result, _ = db.cypher_query(
                '''
                MATCH (h:HarnessInputNode) -[:COVERS]-> (f:CFGFunction)
                WHERE h.identifier = $identifier
                return  count(f)
                ''',
                {'identifier': harness_input.identifier}
            )
            try:
                covered_functions = result[0][0]
            except IndexError:
                continue

            # this is a list of deduplicated function names
            if covered_functions == 0:
                benign_harness_inputs_no_coverage.append(harness_input)
                continue
            if all_benign_num == EXPECTED_BENIGN_INPUTS_NUM:
                break
            all_benign_num += 1

        for harness_input in benign_harness_inputs[:EXPECTED_BENIGN_INPUTS_NUM]:
            covered_functions = harness_input.covered_functions.all()
            # this is a list of deduplicated function names
            covered_function_keys = [func.identifier for func in covered_functions]
            seen_funcs = []
            for func in covered_function_keys:
                if func in seen_funcs:
                    continue
                seen_funcs.append(func)
                if func in tmp_func_in_benign_input_to_num:
                    tmp_func_in_benign_input_to_num[func] += 1
                else:
                    tmp_func_in_benign_input_to_num[func] = 1


        all_benign_num = max(1, all_benign_num)
        all_benign_func_key = list(tmp_func_in_benign_input_to_num.keys())
        # convert everything to src key
        matching_indices, not_found = self.program.code._function_resolver.find_matching_indices(all_benign_func_key, scope='focus', can_include_build_generated=False)
        for func_key in all_benign_func_key:
            if func_key not in not_found:
                new_func_key = matching_indices[func_key]
                func_in_benign_input_to_num[new_func_key] = tmp_func_in_benign_input_to_num[func_key]
        _l.info(f"Traced {all_benign_num} benign inputs with coverage")
        # trace benign inputs without coverage to get the coverage information if the number of benign inputs is less than EXPECTED_BENIGN_INPUTS_NUM
        # if all_benign_num < EXPECTED_BENIGN_INPUTS_NUM and len(benign_harness_inputs_no_coverage) > 0:
        #     benign_harness_inputs_no_coverage_to_trace = benign_harness_inputs_no_coverage[
        #                                                  :EXPECTED_BENIGN_INPUTS_NUM - all_benign_num]
        #     file_name_to_trace = []
        #     for i, harness_input in enumerate(benign_harness_inputs_no_coverage_to_trace):
        #         content = bytes.fromhex(harness_input.content_hex)
        #         with open(f"{temp_dir_for_tracing}/{i}", "wb") as f:
        #             f.write(content)
        #         file_name_to_trace.append(f"{temp_dir_for_tracing}/{i}")
        #     tmp_dir = tempfile.TemporaryDirectory(dir="/shared/kumushi")
        #     # copy the coverage build project path to the temporary directory
        #     os.system(
        #         f"rsync -a --ignore-missing-args {self.coverage_build_project_path}/ {tmp_dir.name}")
        #     _l.info(f"doing rsync -a --ignore-missing-args {self.coverage_build_project_path}/ {tmp_dir.name} ")
        #     new_coverage_build_dir = Path(tmp_dir.name)
        #     _l.info("Start Tracing Benign Inputs without Coverage")
        #     with Pintracer(new_coverage_build_dir, harness_name=self.harness_name, debug_mode=True,
        #                    full_function_mode=True, aggregate=False, return_func_json=True) as tracer:
        #         covered_funcs_all_seeds = tracer.trace(*file_name_to_trace)
        #         covered_func_keys_all_seeds = self.resolve_covered_functions(covered_funcs_all_seeds)
        #         for covered_funcs in covered_func_keys_all_seeds:
        #             for func in covered_funcs:
        #                 if func in func_in_benign_input_to_num:
        #                     func_in_benign_input_to_num[func] += 1
        #                 else:
        #                     func_in_benign_input_to_num[func] = 1
        #     _l.info(f"Traced {all_benign_num} benign inputs")
        # Get the covered functions of the crashing inputs
        if self.crashing_input_dir:
            crash_dir = self.crashing_input_dir
        else:
            _l.info("No crashing input dir specified, return none.")
            return None, None
        all_crashing_seeds = [crash_dir / f for f in os.listdir(crash_dir) if
                              not f.startswith('.') and not f.endswith('README.txt') and f.startswith('id')]
        all_crashing_num = len(all_crashing_seeds)
        if all_crashing_num > EXPECTED_CRASHING_INPUTS_NUM:
            all_crashing_seeds = all_crashing_seeds[:EXPECTED_CRASHING_INPUTS_NUM]
        func_in_crashing_input_to_num = {}

        # trace all seeds and collect coverage information (with function-level granularity)
        # copy the coverage build project path to /shared, make a temporary directory
        # tmp_dir = tempfile.TemporaryDirectory(dir="/shared/kumushi")
        # # copy the coverage build project path to the temporary directory
        # os.system(
        #     f"rsync -a --ignore-missing-args {self.coverage_build_project_path}/ {tmp_dir.name}")
        # _l.info(f"doing rsync -a --ignore-missing-args {self.coverage_build_project_path}/ {tmp_dir.name} ")
        # new_coverage_build_dir = Path(tmp_dir.name)
        #
        # instrumentation = CoverageFastInstrumentation()
        # instr_project = InstrumentedOssFuzzProject(
        #     instrumentation,
        #     new_coverage_build_dir)

        _l.info(f"Start Tracing {all_crashing_num} Crashing Seeds")
        if all_crashing_num == 0:
            return {}, {}
        crashing_inputs = []
        all_crashing_num = max(1, all_crashing_num)
        trace_start_time = time.time()
        for crashing_seed in all_crashing_seeds:
            with open(crashing_seed, "rb") as f:
                data = f.read()
            crashing_input = ProgramInput(data, ProgramInputType.STDIN)
            crashing_inputs.append(crashing_input)
        tracer = FlexibleTracer(self.program, analysis_name="Aurora")
        tracing_func_names = tracer.trace_many(crashing_inputs, name_only=True)
        for func_names in tracing_func_names.values():
            start_time = time.time()
            unique_func_names = set(func_names)
            covered_func_keys_all_seeds = self.resolve_covered_functions(unique_func_names)
            seen_funcs = []
            for func in covered_func_keys_all_seeds:
                if func in seen_funcs:
                    continue
                seen_funcs.append(func)
                if func in func_in_crashing_input_to_num:
                    func_in_crashing_input_to_num[func] += 1
                else:
                    func_in_crashing_input_to_num[func] = 1
            elapsed_time = time.time() - start_time
            _l.info(f"Resolved {len(unique_func_names)} functions in {elapsed_time:.2f} seconds")
        _l.info(f"Traced {len(all_crashing_seeds)} crashing seeds and takes {time.time() - trace_start_time:.2f} seconds")
        func_score = {}

        for func in func_in_crashing_input_to_num:
            if func in func_in_benign_input_to_num:
                # the bigger propotion that the func in crashing seeds, the smaller propotion that the func in benign seeds, the bigger the score
                func_score[func] = func_in_crashing_input_to_num[func] / all_crashing_num - (
                        func_in_benign_input_to_num[func] / all_benign_num)
            else:
                func_score[func] = func_in_crashing_input_to_num[func] / all_crashing_num
        for func in func_in_benign_input_to_num:
            if func not in func_in_crashing_input_to_num:
                # set to -infinity if the func is not in crashing seeds
                func_score[func] = float('-inf')
        sorted_func_score = dict(sorted(func_score.items(), key=lambda x: x[1], reverse=True))
        sorted_func_to_num = {}
        for func in sorted_func_score:
            sorted_func_to_num[func] = [func_in_crashing_input_to_num.get(func, 0),
                                        func_in_benign_input_to_num.get(func, 0)]
        return sorted_func_score, sorted_func_to_num
