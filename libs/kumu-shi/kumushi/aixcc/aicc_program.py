import json
import logging
import shutil
import tempfile
import typing
from pathlib import Path
from typing import List, Optional, Tuple
import requests
import os

import yaml
from git import Repo, InvalidGitRepositoryError, NoSuchPathError
from shellphish_crs_utils.models import POIReport, PatchRequestMeta, RootCauseReport
from shellphish_crs_utils.models.oss_fuzz import AugmentedProjectMetadata
from shellphish_crs_utils.models.testguy import TestGuyLibMetaData


from kumushi.data.program_input import ProgramInput, ProgramInputType
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from shellphish_crs_utils.function_resolver import LocalFunctionResolver, RemoteFunctionResolver, FunctionResolver

from kumushi.data.program import Program

from ..data.program_alert import ProgramExitType, ProgramAlert

if typing.TYPE_CHECKING:
    from . import AICCProgram

_l = logging.getLogger(__name__)


class AICCProgram(Program):
    """
    AIxCC Edition of Program

    """

    def __init__(
        self,
        target_project: OSSFuzzProject,
        source_root: Path,
        harness_name: str = None,
        sanitizer_string: str = None,
        coverage_build_project_path: Path = None,
        debug_build_project_path: Path = None,
        aflpp_build_project_path: Path = None,
        delta_mode: bool = False,
        poi_report: POIReport = None,
        project_metadata: AugmentedProjectMetadata = None,
        local_run: bool = False,
        function_resolver: FunctionResolver = None,
        functions_by_commit_jsons_dir: Path = None,
        indices_by_commit_path: Path = None,
        diffguy_funcs: list = None,patch_request_metadata: PatchRequestMeta = None,
        crashing_input_dir: Path = None,
        previously_built: bool = False,
        dyva_report: RootCauseReport = None,
        bypassing_input_path: Path = None,
        should_init_resolver: bool = False,
        build_checker_works: bool = False,
        **kwargs,
    ):
        super().__init__(source_root, function_resolver=function_resolver, should_init_resolver=should_init_resolver, **kwargs)
        self.target_project = target_project
        self.harness_name = harness_name
        self.sanitizer_string = sanitizer_string
        self._previously_built = previously_built
        self.coverage_build_project_path = coverage_build_project_path
        self.debug_build_project_path = debug_build_project_path
        self.aflpp_build_project_path = aflpp_build_project_path
        self.delta_mode = delta_mode
        self.poi_report = poi_report
        self.project_metadata = project_metadata
        self.local_run = local_run
        self.functions_by_commit_jsons_dir = functions_by_commit_jsons_dir
        self.indices_by_commit_path = indices_by_commit_path
        self.diffguy_funcs = diffguy_funcs
        self.patch_request_metadata = patch_request_metadata
        self.crashing_input_dir = Path(crashing_input_dir) if crashing_input_dir else None
        self.dyva_report = dyva_report
        self.crashing_function = self._recover_crashing_function_name()
        self.bypassing_input_path = bypassing_input_path
        self.build_checker_works = build_checker_works

    def _recover_crashing_function_name(self) -> Optional[str]:
        if self.poi_report and self.poi_report.stack_traces:
            stack_trace = self.poi_report.stack_traces.get("main", None)
            if stack_trace:
                call_locations = stack_trace.call_locations
                if call_locations and call_locations[0].source_location is not None and call_locations[0].source_location.function_name:
                    return call_locations[0].source_location.function_name

        _l.critical("Failed to recover crashing function name from POI report. This is unexpected!")
        return None

    def copy(self, pre_built=False, **kwargs) -> "AICCProgram":
        Path(f"/shared/patchery/{self.poi_report.project_id}").mkdir(parents=True, exist_ok=True)
        # first make a central folder for the new source and the new oss fuzz project
        new_dir = Path(tempfile.mkdtemp(dir=f"/shared/patchery/{self.poi_report.project_id}/"))
        # copy the oss fuzz project
        new_oss_fuzz_project_path = new_dir / f"{self.target_project.project_path.name}"
        new_oss_fuzz_project_path.mkdir(parents=True, exist_ok=True)
        shutil.copytree(self.target_project.project_path, new_oss_fuzz_project_path, dirs_exist_ok=True)

        # copy the source code as well
        new_source_path = new_dir / 'source-root'
        new_source_path.mkdir(parents=True, exist_ok=True)
        shutil.copytree(self.source_root, new_source_path, dirs_exist_ok=True)

        # create a new project from the copied directory
        oss_fuzz_project = OSSFuzzProject(
            project_id=self.target_project.project_id,
            oss_fuzz_project_path=new_oss_fuzz_project_path,
            project_source=new_source_path,
            use_task_service=not self.local_run,
        )

        # create a new AICCProgram with the copied project
        new_aicc_program = AICCProgram(
            oss_fuzz_project,
            source_root=new_source_path,
            poi_report=self.poi_report,
            harness_name=self.harness_name,
            sanitizer_string=self.sanitizer_string,
            # TODO: idk how to do the coverage or AFL stuff!
            coverage_build_project_path=self.coverage_build_project_path,
            debug_build_project_path=self.debug_build_project_path,
            aflpp_build_project_path=self.aflpp_build_project_path,
            language=self.language,
            delta_mode=self.delta_mode,
            crashing_inputs=self._crashing_inputs,
            project_metadata=self.project_metadata,
            local_run=self.local_run,
            function_resolver=self.function_resolver,
            functions_by_commit_jsons_dir=self.functions_by_commit_jsons_dir,
            indices_by_commit_path=self.indices_by_commit_path,
            diffguy_funcs=self.diffguy_funcs,
            crashing_input_dir=self.crashing_input_dir,
            previously_built=pre_built,
            patch_request_metadata=self.patch_request_metadata,
            should_init_resolver=self._should_init_resolver,
            build_checker_works=self.build_checker_works,
        )

        # resolver
        new_aicc_program._saved_resolver_cls = self._saved_resolver_cls
        new_aicc_program._saved_resolver_args = self._saved_resolver_args

        return new_aicc_program

    def cleanup(self):
        """
        Only to be used when paired with copy()
        """
        # remove the project directory
        if self.target_project.project_path.exists():
            shutil.rmtree(self.target_project.project_path)

    def check_and_set_build_checker_works(self):
        _l.info("Checking build checker works")
        if not self.poi_report or not self.poi_report.build_configuration_id:
            _l.warning("POI report or build configuration ID is missing, cannot check build checker")
            self.build_checker_works = False
            return

        build_configuration_id = self.poi_report.build_configuration_id
        try:
            import yaml
            resp = requests.get(
                f'{os.environ.get("PDT_AGENT_URL")}/data/verify_build_check_works/build_check_success/{build_configuration_id}',
                timeout=180)
            if resp.status_code == 200:
                check_data = yaml.safe_load(resp.text)
                check_success = check_data.get('runs', None)
                self.build_checker_works = check_success is True
            else:
                self.build_checker_works = False
        except Exception as e:
            import traceback
            traceback.print_exc()
            self.build_checker_works = False

        if not self.build_checker_works:
            _l.warning("Build checker does not work, will not use it for build checking")

    def _build_containers(self):
        if not self._previously_built:
            # build the builder and runner images
            self.target_project.build_builder_image()
            self.target_project.build_runner_image()
            self._previously_built = True

    def _compile_core(self, patch_path: Optional[Path] = None, patch_obj = None, flags=None, **kwargs) -> Tuple[bool, str]:
        self._build_containers()
        print_output = kwargs.get("print_output", False)
        if patch_path is not None:
            patch_path = Path(patch_path).absolute()
        get_cached_build = kwargs.get("get_cached_build", False)

        extra_env = None
        if flags is not None:
            if self.language == "c":
                extra_env = {"CFLAGS": flags}

        build_result = self.target_project.build_target(
            patch_path=str(patch_path), sanitizer=self.sanitizer_string, print_output=print_output, preserve_built_src_dir=True,
            extra_env=extra_env, get_cached_build=get_cached_build
        )
        if patch_obj is not None and hasattr(patch_obj, "metadata"):
            patch_obj.metadata["build_request_id"] = build_result.build_request_id

        task_success = build_result.task_success
        build_passed = build_result.build_success
        # in local run, task success mand build pass mean the same
        if not build_passed:
            stdout = build_result.stdout.decode(errors='ignore')
            stderr = build_result.stderr.decode(errors='ignore')
            _l.debug(f"Compilation failed: stdout {stdout}")
            _l.debug(f"Compilation failed: stderr {stderr}")
            # FIXME: actual compilation output is saved in self.target_project.artifacts_dir_docker
            reason = f"Compilation failed.\n" + f'{stderr}'
            if self.language == "jvm":
                reason = ""
                lines = stdout.replace("\\n", "\n").split("\n")
                for line in lines:
                    if line.startswith(" [ERROR]"):
                        reason += line + "\n"
            return build_passed, reason

        if not task_success:
            _l.debug(f"Task failed: retry once")
            if patch_path is not None:
                patch_path = Path(patch_path).absolute()
            build_result = self.target_project.build_target(
                patch_path=str(patch_path), sanitizer=self.sanitizer_string, print_output=False, preserve_built_src_dir=True
            )
            task_success = build_result.task_success
            build_passed = build_result.build_success
            if not task_success:
                _l.debug(f"Task failed: retry failed")
                return False, "Task failed: retry failed"

        reason = "Successful compilation."
        return build_passed, reason

    def setup_program(self):
        Path(f"/shared/patchery/{self.poi_report.project_id}").mkdir(parents=True, exist_ok=True)
        assert self.target_project.project_source and self.target_project.project_source.exists(), f"Missing project source: {self.target_project.project_source}"
        self.target_project.project_source = Path(self.target_project.project_source).absolute()
        assert self.target_project.project_source.is_dir(), f"Project source is not a directory: {self.target_project.project_source}"

        try:
            worked = Repo(self.target_project.project_source).git_dir
            is_git_repo = worked
        except (InvalidGitRepositoryError, NoSuchPathError):
            is_git_repo = False

        if not is_git_repo:
            try:
                Repo.init(self.target_project.project_source)
            except Exception as e:
                raise Exception(f"Failed to initialize git repository at {self.target_project.project_source}: {e}")

        self._build_containers()

    def generates_alerts(self, prog_input: "ProgramInput") -> Tuple[ProgramExitType, str | None, list[str]]:
        raw_data = prog_input.data.encode() if isinstance(prog_input.data, str) else prog_input.data
        run_pov_res = self.target_project.run_pov(
            harness=self.harness_name, data=raw_data,
            sanitizer=self.sanitizer_string,
            fuzzing_engine=self.project_metadata.shellphish.fuzzing_engine.value,
            timeout=30
        )
        pov = run_pov_res.pov
        pov_report_data = None
        stack_trace_functions = []
        if run_pov_res.run_exit_code == 124:
            _l.info("Program Timeout")
            return ProgramExitType.TIMEOUT, None, stack_trace_functions

        if pov is not None:
            if pov.crash_report is not None and pov.crash_report.stack_traces:
                main_stack_trace = pov.crash_report.stack_traces.get("main", None)
                if main_stack_trace is not None and main_stack_trace.call_locations:
                    for call_location in main_stack_trace.call_locations:
                        if call_location.source_location and call_location.source_location.function_name:
                            stack_trace_functions.append(call_location.source_location.function_name)
                        else:
                            stack_trace_functions.append("")


        if pov.triggered_sanitizers:
            pov_report_data = pov.crash_report.raw_report or pov.unparsed
            if isinstance(pov_report_data, bytes):
                pov_report_data = pov_report_data.decode("utf-8", errors="ignore")
            alert = ProgramAlert(ProgramExitType.TRIGGERED, "", pov_report_data)
        else:
            alert = ProgramAlert(ProgramExitType.NORMAL, "", "")

        return alert._exit_type, pov_report_data, stack_trace_functions

    def execute(self, prog_input: "ProgramInput") -> tuple[str, str]:
        raw_data = prog_input.data.encode() if isinstance(prog_input.data, str) else prog_input.data
        run_pov_res = self.target_project.run_pov(
            harness=self.harness_name, data=raw_data, print_output=False, sanitizer=self.sanitizer_string,
            fuzzing_engine=self.project_metadata.shellphish.fuzzing_engine.value
        )
        return run_pov_res.stdout, run_pov_res.stderr

    def _check_functionality_core(self, patch_path: Optional[Path] = None, **kwargs) -> tuple[ProgramExitType, Optional[str]]:
        run_result = self.target_project.run_tests(
            patch_path=patch_path,
            sanitizer=self.sanitizer_string,
            print_output=False,
        )
        if run_result.tests_exist:
            output = run_result.stderr or run_result.stdout
            return (ProgramExitType.NORMAL, None) if run_result.all_passed else (ProgramExitType.TEST_FAILED, output)
        else:
            return ProgramExitType.NORMAL, None

    def retrive_refine_patch(self, patch_id: str) -> str | None:
        return None

    def apply_refine_patch(self) -> bool | None:
        if self.patch_request_metadata is not None:
            if self.patch_request_metadata.request_type != "refine":
                return None
            patch_id = self.patch_request_metadata.patch_id
            patch_diff = self.retrive_refine_patch(patch_id)
            if patch_diff is None:
                return None
            Repo(self.target_project.project_source).git.apply(patch_diff)
            return True
        return None

    @classmethod
    def from_files(
            cls,
            source_root: Path,
            # artiphishell generated files
            ossfuzz_project_root: Path,
            metadata_path: Path,
            poi_report_path: Path,
            function_indices: Path,
            function_json_dir: Path,
            indices_by_commit: Path | None = None,
            functions_by_commit_jsons_dir: Path | None = None,
            delta_mode: bool = False,
            # general
            crashing_input_paths: List[Path] = None,
            benign_input_paths: List[Path] = None,
            # coverage
            coverage_build_project_path: Path = None,
            aflpp_build_project_path: Path = None,
            local_run: bool = False,
            # diffguy
            diffguy_report_path: Path = None,
            patch_request_meta: Path = None,
            # crash_exploration
            crashing_input_dir: Path = None,
            debug_build_project_path: Path = None,
            # dyva
            dyva_report_path: Path = None,
            # bypassings inputs
            bypassing_input_path: Path = None,
            should_init_resolver: bool = False,
            **kwargs,
    ):
        # fix paths and assert they exist when mandatory
        source_root = Path(source_root).absolute()
        assert source_root.exists(), f"Source root does not exist: {source_root}"
        ossfuzz_project_root = Path(ossfuzz_project_root).absolute()
        assert ossfuzz_project_root.exists(), f"OSSFuzz project root does not exist: {ossfuzz_project_root}"
        metadata_path = Path(metadata_path).absolute()
        assert metadata_path.exists(), f"Metadata path does not exist: {metadata_path}"
        poi_report_path = Path(poi_report_path).absolute()
        assert poi_report_path.exists(), f"POI report path does not exist: {poi_report_path}"
        if indices_by_commit is not None:
            indices_by_commit = Path(indices_by_commit).absolute()
            assert indices_by_commit.exists(), f"indices_by_commit path does not exist: {indices_by_commit}"
        if functions_by_commit_jsons_dir is not None:
            functions_by_commit_jsons_dir = Path(functions_by_commit_jsons_dir).absolute()
            assert functions_by_commit_jsons_dir.exists(), f"functions_by_commit_jsons_dir path does not exist: {functions_by_commit_jsons_dir}"
        _l.info("Loading AICCProgram from files")

        # read the project metadata
        with metadata_path.open("r") as f:
            project_metadata_data = AugmentedProjectMetadata.model_validate(yaml.safe_load(f))

        # read the poi report data
        with open(poi_report_path, "r") as f:
            # rep = yaml.safe_load(f)

            #rep["organizer_crash_eval"] = {}
            #rep["organizer_crash_eval"]["code_label"] = ""
            #rep["organizer_crash_eval"]["significance"] = 0
            #rep["organizer_crash_eval"]["significance_message"] = ""
            #rep["organizer_crash_eval"]["crash_state"] = ""
            poi_report_data = POIReport.model_validate(yaml.safe_load(f))

        # read all the input files
        benign_inputs = []
        crashing_inputs = []
        if benign_input_paths is not None:
            benign_input_paths = [Path(p).absolute() for p in benign_input_paths]
            for input_file in benign_input_paths:
                with open(input_file, "rb") as f:
                    benign_inputs.append(ProgramInput(f.read(), ProgramInputType.FILE))
        if crashing_input_paths is not None:
            if isinstance(crashing_input_paths, list):
                crashing_input_paths = [Path(p).absolute() for p in crashing_input_paths]
                for input_file in crashing_input_paths:
                    with open(input_file, "rb") as f:
                        crashing_inputs.append(ProgramInput(f.read(), ProgramInputType.FILE))
            elif isinstance(crashing_input_paths, str):
                crashing_input_paths = Path(crashing_input_paths).absolute()
                with open(crashing_input_paths, "rb") as f:
                    crashing_inputs.append(ProgramInput(f.read(), ProgramInputType.FILE))

        # load the ossfuzz project
        oss_fuzz_project = OSSFuzzProject(
            project_id=poi_report_data.project_id,
            oss_fuzz_project_path=ossfuzz_project_root,
            project_source=source_root,
            use_task_service=not local_run,
        )
        #oss_fuzz_project.project_metadata.shellphish_project_name = "nginx"

        # read the clang info
        if local_run:
            function_indices = Path(function_indices).absolute()
            assert function_indices.exists(), f"Function indices path does not exist: {function_indices}"
            function_json_dir = Path(function_json_dir).absolute()
            assert function_json_dir.exists(), f"Function JSON directory does not exist: {function_json_dir}"
            function_resolver = LocalFunctionResolver(str(function_indices.resolve()), str(function_json_dir.resolve()))
        else:
            function_resolver = RemoteFunctionResolver(poi_report_data.project_name, poi_report_data.project_id)

        # read diff guy report
        diffguy_funcs = None
        if diffguy_report_path is not None:
            with open(diffguy_report_path, "r") as f:
                tmp = json.load(f)
            diffguy_funcs = []
            if 'overlap' in tmp and tmp['overlap']:
                diffguy_funcs = tmp['overlap']
            elif 'heuristic' in tmp and tmp['heuristic']:
                diffguy_funcs = tmp['heuristic']
            elif 'union' in tmp and tmp['union']:
                diffguy_funcs = tmp['union']
        patch_request_metadata = None
        if patch_request_meta is not None and not Path(patch_request_meta).is_dir():
            with open(patch_request_meta, "r") as f:
                data = yaml.safe_load(f)

                #data["bucket_id"] = "dank"
                #if "crashing_inputs_keys" in data:
                #    del data["crashing_inputs_keys"]
                #del data["harness_info_id"]
                #del data["project_id"]
                #del data["project_name"]

                patch_request_metadata = PatchRequestMeta.model_validate(data)
        dyva_report_data = None
        if dyva_report_path is not None and not Path(dyva_report_path).is_dir():
            with open(dyva_report_path, "r") as f:
                dyva_report_data = RootCauseReport.model_validate(yaml.safe_load(f))

        return cls(
            oss_fuzz_project,
            source_root=source_root,
            poi_report=poi_report_data,
            harness_name=poi_report_data.cp_harness_name,
            sanitizer_string=str(poi_report_data.sanitizer.value),
            coverage_build_project_path=coverage_build_project_path,
            debug_build_project_path=debug_build_project_path,
            aflpp_build_project_path=aflpp_build_project_path,
            language=project_metadata_data.language.name.lower(),
            delta_mode=delta_mode,
            crashing_inputs=crashing_inputs,
            project_metadata=project_metadata_data,
            local_run=local_run,
            function_resolver=function_resolver,
            functions_by_commit_jsons_dir=functions_by_commit_jsons_dir,
            indices_by_commit_path=indices_by_commit,
            diffguy_funcs=diffguy_funcs,
            patch_request_metadata=patch_request_metadata,
            crashing_input_dir=crashing_input_dir,
            dyva_report=dyva_report_data,
            bypassing_input_path=bypassing_input_path,
            should_init_resolver=should_init_resolver,
        )
