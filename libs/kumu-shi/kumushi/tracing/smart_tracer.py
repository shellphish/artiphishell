import tempfile
import logging
import os
from typing import Optional, Union

from kumushi.tracing.abstract_tracer import AbstractTracer

_l = logging.getLogger(__name__)
from pathlib import Path
from kumushi.aixcc import AICCProgram
from kumushi.data import PoI, PoISource, ProgramInput
from shellphish_crs_utils.oss_fuzz.project import InstrumentedOssFuzzProject, OSSFuzzProject
from shellphish_crs_utils.oss_fuzz.instrumentation.coverage_fast import CoverageFastInstrumentation

COVERAGE_LIB_AVAILABLE = True
try:
    from coveragelib.parsers.calltrace_coverage import Java_Calltrace_Yajta
    from coveragelib.yajta import Yajta
    from coveragelib.pintrace import PintracerWithSanitizer, Pintracer
except ImportError as e:
    _l.warning(f"Coverage library not available: {e}")
    COVERAGE_LIB_AVAILABLE = False


class SmartCallTracer(AbstractTracer):
    def __init__(self, program: AICCProgram):
        super().__init__(program)
        if not COVERAGE_LIB_AVAILABLE:
            raise ImportError("Coverage library is not available. Please install it to use SmartCallTracer.")
        self._saved_tracer = None

    def _trace(self, program_input: ProgramInput, **kwargs) -> list[PoI]:
        if self._saved_tracer is None:
            raise RuntimeError("Tracer is not initialized. Call instrument() first.")
        _l.info(f"using pin tracer to trace")
        _, input_file_path = tempfile.mkstemp()
        with open(input_file_path, "wb") as f:
            f.write(program_input.data)

        with self._saved_tracer:
            pois = self._trace_in_context(input_file_path)

        return pois

    def instrument(self, expect_crashing=True, **kwargs) -> object:
        if self.program.project_metadata.language == "c" or self.program.project_metadata.language == "c++":
            os.makedirs(f"/shared/kumushi/{self.program.poi_report.project_id}", exist_ok=True)
            sanitizer_build_path = Path(
                tempfile.TemporaryDirectory(dir=f"/shared/kumushi/{self.program.poi_report.project_id}").name)
            coverage_build_path = Path(
                tempfile.TemporaryDirectory(dir=f"/shared/kumushi/{self.program.poi_report.project_id}").name)
            os.system(
                f"rsync -a --delete --ignore-missing-args {self.program.coverage_build_project_path} {coverage_build_path}")
            os.system(
                f"rsync -a --delete --ignore-missing-args {self.program.debug_build_project_path} {sanitizer_build_path}")
            if expect_crashing:
                debug_project = OSSFuzzProject(
                    sanitizer_build_path, self.program.source_root, self.program.poi_report.project_id,
                    self.program.project_metadata, use_task_service=not self.program.local_run
                )
                debug_project.build_builder_image()
                debug_project.build_runner_image()
                instrumentation = CoverageFastInstrumentation()
                instr_project = InstrumentedOssFuzzProject(instrumentation, coverage_build_path)

                _l.info(f"Using PinTracer with Sanitizer (for crashing inputs)")
                pintracer = PintracerWithSanitizer(
                    oss_fuzz_project=debug_project,
                    coverage_oss_fuzz_project=instr_project,
                    harness_name=self.program.poi_report.cp_harness_name,
                    debug_mode=False,
                    aggregate=False,
                    trace_inlines=True,
                    full_function_mode=True,
                    return_func_json=False,
                    use_rio=False
                )
            else:
                _l.info(f"Using PinTracer (for non-crashing inputs)")
                pintracer = Pintracer(
                    coverage_build_path,
                    harness_name=self.program.harness_name,
                    debug_mode=False,
                    full_function_mode=True,
                    aggregate=False,
                    return_func_json=False,
                )
            tracer = pintracer
        elif self.program.code.language == "jvm":
            _l.info("Using Yajta tracer for JVM/Java")
            parser = Java_Calltrace_Yajta()
            tracer = Yajta(
                self.program.coverage_build_project_path, self.program.harness_name, parser=parser,
                debug_mode=False, crash_mode=True
            )
        else:
            raise ValueError("Unsupported language for SmartCallTracer")

        self._saved_tracer = tracer

    def trace_many(self, program_inputs: list[ProgramInput], name_only=False, **kwargs) -> dict[ProgramInput, list[PoI]]:
        if self._saved_tracer is None:
            self.instrument(**kwargs)

        traces = {}
        with self._saved_tracer:
            if isinstance(self._saved_tracer, PintracerWithSanitizer):
                program_inputs = program_inputs[:30]
            for program_input in program_inputs:
                _, input_file_path = tempfile.mkstemp()
                with open(input_file_path, "wb") as f:
                    f.write(program_input.data)

                pois = self._trace_in_context(input_file_path, name_only)
                traces[program_input] = pois

        return traces

    def _trace_in_context(self, program_input_path: Union[Path, str], name_only=False) -> list[PoI] | list[str]:
        covered_funcs = self._saved_tracer.trace(str(program_input_path))
        if self.program.project_metadata.language == "c" or self.program.project_metadata.language == "c++":
            if name_only:
                return covered_funcs
            seed_name = Path(program_input_path).name
            return self._parse_c_trace(covered_funcs[str(seed_name)])
        elif self.program.code.language in ["jvm", "java"]:
            return self._parse_java_trace(covered_funcs, name_only)
        else:
            raise ValueError("Unsupported language for SmartCallTracer")

    def _parse_c_trace(self, covered_funcs: list) -> list[PoI]:
        if len(covered_funcs) == 0:
            return []
        pois = []
        func_set = set(covered_funcs)
        func_dict = {}
        # quickly find the functions in the code
        for func in func_set:
            functions = self.program.code.functions_by_name(func)
            if not functions:
                continue
            if func not in func_dict:
                func_dict[func] = functions[0]
        for func in covered_funcs:
            if func in func_dict:
                code_func = func_dict[func].copy()
                pois.append(PoI(
                    function=code_func,
                    sources=[PoISource.CALL_TRACE],
                ))
        return pois

    def _clean_method_path(self, funcname: str) -> str:
        return funcname.split('(')[0].strip()

    def _clean_funcname(self, funcname: str) -> str:
        return funcname.split("(")[0].rsplit(".", 1)[-1]

    def _parse_java_trace(self, covered_funcs: list, name_only=False) -> list[PoI] | list[str]:
        def dfs_yajta_output(tree:list) -> list[str]:
            # yajta output is a tree, we need to do a dfs to get the order of the functions
            result = []
            def dfs(node):
                name = node.get("name")
                if name:
                    result.append(name)
                for child in node.get("children", []):
                    dfs(child)
            dfs(tree[0])
            return result

        if len(covered_funcs) == 0:
            return []
        dfs_ordered_covered_funcs = dfs_yajta_output(covered_funcs)
        if name_only:
            return dfs_ordered_covered_funcs
        pois = []
        for funcname in dfs_ordered_covered_funcs:
            full_method_path = self._clean_method_path(funcname)
            clean_funcname = self._clean_funcname(funcname)
            functions = self.program.code.functions_by_name(clean_funcname, focus_repo_only=True, java_full_method=full_method_path)
            if not functions:
                continue
            for func in functions:
                pois.append(PoI(
                    function=func,
                    sources=[PoISource.CALL_TRACE],
                ))
        return pois

