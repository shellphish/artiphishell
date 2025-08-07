import argparse
import shutil
import subprocess
import logging
import tempfile
from typing import Optional
import yaml
import json
import os
import uuid
from pathlib import Path

import patchery
from patchery import ProgramInput, Patcher
from patchery.data import ProgramPOI, ProgramInputType, AICCProgramInfo, InvarianceReport
from patchery.utils import absolute_path_finder, read_src_from_file, find_src_root_from_commit
from patchery.report_analyzer import ReportAnalyzer, AsanParser, KasanParser, ReportType
from patchery.code_parsing import CodeParser
from patchery.ranker.patch_ranker import PatchRanker

_l = logging.getLogger("patchery")
_l.setLevel(logging.DEBUG)


def main():
    parser = argparse.ArgumentParser(
        description="""
        The PatcherY CLI, useful for patching based on TOML reports.
        """,
        epilog="""
        Examples:
        patchery --version
        """,
    )
    parser.add_argument("--version", "-v", action="version", version=patchery.__version__)

    #
    # Mode Selection
    #

    parser.add_argument(
        "--rank-patches",
        type=Path,
        help="""
        Ranks the patches in the given directory. Uses --rank-output-file to save the results.
        """,
    )

    parser.add_argument(
        "--generate-aixcc-patch",
        action="store_true",
        help="""
        Generate verified patches. Requires the following arguments:
        --src-root, --poi-file, --poi-func, --poi-line, --run-script --report-file --raw-report
        """,
    )

    #
    # AIxCC Patch Generation
    #

    parser.add_argument(
        "--report-yaml",
        type=Path,
        help="""
        """,
    )
    parser.add_argument(
        "--target-root",
        type=Path,
        help="The root directory of the target in which the patches will be applied.",
    )
    parser.add_argument(
        "--function-json-dir",
        type=Path,
        help="Path to the directory that contain all functions/classes/methods of the target",
    )
    parser.add_argument(
        "--functions-by-commit-jsons-dir",
        type=Path,
        help="Path to the directory that contain the functions/classes/methods of the target for each commit",
    )
    parser.add_argument(
        "--function-indices",
        type=Path,
        help="Path to the json file with info on the PoI function/method",
    )
    parser.add_argument(
        "--indices-by-commit", type=Path, help="Path to the indices of changed functions for each commit"
    )
    parser.add_argument(
        "--sanitizer-string",
        type=str,
        help="The sanitizer string used in the report",
    )

    #
    # Execution (verification) Information
    #

    parser.add_argument(
        "--benign-inputs",
        type=Path,
        help="The path to the benign inputs.",
    )
    parser.add_argument(
        "--alerting-inputs",
        type=Path,
        help="The path to the alerting inputs.",
    )

    #
    # Ranking flags
    #
    parser.add_argument(
        "--rank-patch-verifications",
        type=Path,
        help="""
        Directory of files containing amount of times a patch crashed on other inputs.
        """,
    )
    parser.add_argument(
        "--rank-patch-metadatas",
        type=Path,
        help="""
        Metadata of the patches to rank.
        """,
    )
    parser.add_argument(
        "--rank-output-dir",
        type=Path,
        help="""
        The directory to save the ranked patches. Should be used with --rank-patches. Each rank file will be named
        `patch_rank_<timestamp>.json`, where the timestamp is the time the rank was generated. We deciding the best
        patch based on the ranking, always use the latest rank file.
        """,
    )
    parser.add_argument(
        "--continuous-ranking",
        action="store_true",
        default=False,
        help="""
        If set, the patcher will continuously rank patches in the directory until a timeout is reached.
        """,
    )
    parser.add_argument(
        "--rank-timeout",
        type=int,
        help="""
        The time in seconds to rank patches. Only used with --continuous-ranking.
        """,
    )
    parser.add_argument(
        "--rank-wait-time",
        type=int,
        help="""
        The time in seconds to wait between ranking patches. Only used with --continuous-ranking.
        """,
    )

    #
    # Optional args for targets
    #

    parser.add_argument(
        "--c-reproducer-folder",
        help="The path to the folder containing the C reproducer files.",
    )
    parser.add_argument(
        "--kernel-image-dir",
        help="The path of the kernel bzImage file.",
    )
    parser.add_argument(
        "--patch-output-dir",
        type=Path,
        help="The path to save the verified patch.",
    )
    parser.add_argument("--patch-meta-output-dir", type=Path, help="The path to save the patch metadata")
    parser.add_argument(
        "--raw-report",
        type=Path,
        help="The path to the raw report file.",
    )
    parser.add_argument(
        "--vds-record-id",
        type=str,
        help="The ID of the VDS submitted to CAPI.",
    )
    parser.add_argument(
        "--crashing-commit",
        help="The commit that caused the crash.",
    )
    parser.add_argument(
        "--invariance-report",
        type=Path,
        help="The path to the invariance report.",
    )
    parser.add_argument(
        "--debug-report",
        type=Path,
        help="The path to the debug report.",
    )
    parser.add_argument(
        "--max-attempts",
        type=int,
        help="Number of attempts for one poi.",
    )
    parser.add_argument(
        "--max-pois",
        type=int,
        help="Number of pois to patch.",
    )

    args = parser.parse_args()
    if args.generate_aixcc_patch:
        # validate we have the args we need for operation
        required_args = [
            # "report_yaml",
            # "raw_report",
            # "target_root",
            # "function_json_dir",
            # "function_indices",
            # "vds_record_id",
            # "patch_output_dir",
            # "crashing_commit"
            "sanitizer_string"
        ]

        for arg_attr in required_args:
            arg = getattr(args, arg_attr)
            if arg is None:
                raise ValueError(f"Missing required argument: {arg_attr}. Args must include: {required_args}")

        patch_generated = generate_patches_from_aicc_files(
            args.target_root,
            args.report_yaml,
            sanitizer_string=args.sanitizer_string,
            raw_report=args.raw_report,
            function_json_dir=args.function_json_dir,
            function_indices=args.function_indices,
            alerting_inputs_path=args.alerting_inputs,
            benign_inputs_path=args.benign_inputs,
            patch_output_dir=args.patch_output_dir,
            patch_metadata_output_dir=args.patch_meta_output_dir,
            c_reproducer_folder=args.c_reproducer_folder,
            kernel_image_dir=args.kernel_image_dir,
            invariance_report=args.invariance_report,
            crashing_commit=args.crashing_commit,
            indices_by_commit=args.indices_by_commit,
            changed_func_by_commit=args.functions_by_commit_jsons_dir,
            debug_report=args.debug_report,
            max_attempts=args.max_attempts,
            max_pois=args.max_pois
        )
        if patch_generated:
            _l.debug("Success. Patch generated.")
            exit(0)
        else:
            _l.warning("No patch generated. Exiting with error!")
            exit(1)
    elif args.rank_patches:
        if not args.rank_patches.exists():
            _l.error(f"Patch directory {args.rank_patches} does not exist.")
            return

        try:
            PatchRanker.rank_many_aicc_patch_dirs(
                patches_dir=args.rank_patches,
                previous_crashes_dir=args.rank_patch_verifications,
                patch_metadatas_dir=args.rank_patch_metadatas,
                continuous=args.continuous_ranking,
                rank_output_dir=args.rank_output_dir,
                wait_time=args.rank_wait_time,
                timeout=args.rank_timeout,
            )
        except Exception:
            _l.error("Error when ranking patches", exc_info=True)
        return
    else:

        args.display_help()


#
# Utils
#


def _correct_string_paths(*args):
    out = []
    for arg in args:
        if isinstance(arg, str):
            if not arg or arg == "None":
                out.append(None)
            else:
                pathed_arg = Path(arg)
                if not pathed_arg.exists():
                    _l.warning(f"Path {pathed_arg} does not exist!")
                out.append(Path(arg))
            continue
        else:
            out.append(arg)

    return out


def _resolve_abs_path_from_pois(pois: list, target_root: Path, report_data: dict, commit=None):
    # first attempt to go through every POI and find the absolute path
    COMMIT_RECOVERED_POI_FUNC_PLACEHOLDER = "PLACEHOLDER"
    abs_src_path = None
    invalid_poi_idxs = set()
    path_suffix = None
    relative_file_path = None
    for i, poi in enumerate(pois):
        relative_file_path = poi.get("source_location", {}).get("relative_file_path", None)
        if relative_file_path is None:
            # some pois from other componenets can have this
            relative_file_path = poi.get("relative_file_path", None)
            if relative_file_path is None:
                _l.debug("Found an invalid POI with no source file %s, we are discarding it.", poi)
                invalid_poi_idxs.add(i)
                continue

        # we have a non-None relative path, let's try to resolve it, AIxCC format:
        abs_src_path = target_root / "src" / relative_file_path
        if abs_src_path.exists():
            path_suffix = relative_file_path
            break
        else:
            abs_src_path = None
            _l.debug("Could not find the source file of the POI: %s, skipping...", relative_file_path)
            invalid_poi_idxs.add(i)

    if abs_src_path is not None:
        return abs_src_path, path_suffix, invalid_poi_idxs, None

    # if we still don't have a path, we need to check the report data, if it exists
    new_poi = ProgramPOI(".", None, 0, report=pois[0].get("reason", None) if pois else None)
    new_poi.file = None
    stack_traces = report_data.get("stack_traces", None)
    if stack_traces:
        stack_trace = stack_traces[0]
        call_locations = stack_trace.get("call_locations", [])
        for call_location in call_locations:
            relative_file_path = call_location.get("relative_file_path", None)
            if relative_file_path:
                abs_src_path = target_root / "src" / relative_file_path
                if abs_src_path.exists():
                    new_poi.file = abs_src_path
                    func_name = call_location.get("trace_line", None)
                    new_poi.function = (
                        func_name if not func_name.endswith("_fuzz") else func_name.replace("_fuzz", "")
                    )
                    break
                else:
                    abs_src_path = None

    if abs_src_path is None:
        _l.critical("After iterating all POIs, not a single POI had a resolvable path! Attempting recovery...")
        abs_src_path = find_src_root_from_commit(target_root, commit)
        if abs_src_path is None:
            raise ValueError("All POIs are invalid and last-chance recovery failed! We have no source to work on!")

        relative_file_path = Path(abs_src_path).relative_to(target_root / "src")
        _l.info("Good news! We found a source root %s from the crashing commit: %s", abs_src_path, commit)
        new_poi.function = COMMIT_RECOVERED_POI_FUNC_PLACEHOLDER

    if new_poi.function == COMMIT_RECOVERED_POI_FUNC_PLACEHOLDER:
        new_poi.function = None
    elif new_poi.function is None:
        raise ValueError("After iterating all the POIs, not a single valid function was found in the POIs.")

    return abs_src_path, relative_file_path, invalid_poi_idxs, new_poi


def _parser_poi_report_data(poi_report_data: dict, target_root: Path, commit=None):
    pois = poi_report_data.get("pois", [])
    patching_dir = ""
    # FIXME: This does not consider the scenario where different pois has different root_src ...
    whole_path, suffix, invalid_poi_idxs, new_poi = _resolve_abs_path_from_pois(pois, target_root, poi_report_data, commit=commit)
    for root, dirs, files in os.walk(target_root):
        if ".git" in dirs:
            repo_dir = root
            subprocess.run(
                ["git", "config", "--global", "--add", "safe.directory", repo_dir],
                check=True,
            )

    with open(os.path.join(target_root, "project.yaml"), "r") as f:
        project_yaml = yaml.safe_load(f)

    cp_sources = project_yaml.get("cp_sources").keys()

    # find the root of the source directory by using the POI information we have and seeing
    # if there is anything relative to it
    src_root = None
    for source in cp_sources:
        _src_root = os.path.join(target_root, "src", source)
        if whole_path.is_relative_to(_src_root):
            src_root = _src_root
            patching_dir = source
            break

    if len(patching_dir) < 1:
        raise ValueError(f"Cannot locate cp sources dirctories to patch")
    
    if isinstance(suffix, str):
        filetype = suffix.split(".")[-1]
    elif isinstance(suffix, Path):
        filetype = suffix.suffix.split(".")[-1]
    else:
        _l.critical("We failed to find the filetype of this project! Assuming it's C!!!")
        filetype = "c"

    harness_id = poi_report_data.get("harness_id", "")
    harness_key_word = "name"

    if os.path.exists(os.path.join(target_root, "project.yaml")):
        harness_name = (
            yaml.safe_load(open(os.path.join(target_root, "project.yaml")))
            .get("harnesses", {})
            .get(harness_id, {})
            .get(harness_key_word, "")
        )
    else:
        # This is just place holder for general kernel target
        harness_name = "id_1"
    if harness_name.startswith("out"):
        harness_name = harness_name[4:]

    # verify we can save the patch
    patchery_tmp_dir = Path("/tmp/patchery/")
    if not patchery_tmp_dir.exists():
        patchery_tmp_dir.mkdir()
    tfile = Path(tempfile.mktemp(prefix="patch.", dir=str(patchery_tmp_dir)))
    if tfile.exists():
        raise Exception(f"Patch file {tfile} already exists. This may be a bug, run it again!")
    tfile.write_text("")

    return src_root, filetype, harness_name, harness_id, patching_dir, tfile, invalid_poi_idxs, new_poi


#
# Main runner
#


def generate_patches_from_aicc_files(
    target_root: Path,
    report_yaml: Path,
    sanitizer_string: str = None,
    raw_report: Path = None,
    function_json_dir: Path = None,
    function_indices: Path = None,
    alerting_inputs_path: Path = None,
    benign_inputs_path: Path = None,
    patch_output_dir: Path = None,
    patch_metadata_output_dir: Path = None,
    c_reproducer_folder: Path = None,
    kernel_image_dir: Path = None,
    invariance_report: Path = None,
    crashing_commit: str = None,
    indices_by_commit: Path = None,
    changed_func_by_commit: Path = None,
    debug_report: Path = None,
    max_attempts: int = 10,
    max_pois: int = 8
):
    max_pois = max_pois or 8
    max_attempts = max_attempts or 10
    if patch_output_dir is not None:
        Path(patch_output_dir).mkdir(exist_ok=True)
    if patch_metadata_output_dir is not None:
        Path(patch_metadata_output_dir).mkdir(exist_ok=True)

    # sanity fix 'None' strings and pathify stuff
    (
        target_root,
        report_yaml,
        raw_report,
        function_json_dir,
        function_indices,
        alerting_inputs_path,
        benign_inputs_path,
        patch_output_dir,
        c_reproducer_folder,
        kernel_image_dir,
        invariance_report,
        debug_report,
    ) = _correct_string_paths(
        target_root,
        report_yaml,
        raw_report,
        function_json_dir,
        function_indices,
        alerting_inputs_path,
        benign_inputs_path,
        patch_output_dir,
        c_reproducer_folder,
        kernel_image_dir,
        invariance_report,
        debug_report,
    )

    assert target_root.exists(), f"Target root {target_root} does not exist."
    if not sanitizer_string:
        raise ValueError("Sanitizer string is required to generate patches.")

    function_index = None
    if function_indices is not None:
        with open(function_indices, "r") as f:
            function_index = json.load(f)

    # load all inputs
    benign_inputs = []
    alerting_inputs = []
    invariance_report_data = {}
    debug_report_data = {}
    if benign_inputs_path is not None:
        for input_file in benign_inputs_path.iterdir():
            with open(input_file, "rb") as f:
                benign_inputs.append(ProgramInput(f.read(), ProgramInputType.FILE))
    if alerting_inputs_path is not None:
        if alerting_inputs_path.is_dir():
            for input_file in alerting_inputs_path.iterdir():
                with open(input_file, "rb") as f:
                    alerting_inputs.append(ProgramInput(f.read(), ProgramInputType.FILE))
        elif alerting_inputs_path.is_file():
            with open(alerting_inputs_path, "rb") as f:
                alerting_inputs.append(ProgramInput(f.read(), ProgramInputType.FILE))
    if invariance_report is not None:
        with open(invariance_report, 'r') as f:
            invariance_report_data = yaml.safe_load(f)

    if debug_report is not None:
        with open(debug_report, "r") as f:
            debug_report_data = yaml.safe_load(f)

    # parse kernal args
    has_reproducer = kernel_image_dir is not None and c_reproducer_folder is not None
    kernel_kwargs = (
        {
            "c_reproducer_folder": c_reproducer_folder,
            "kernel_image_dir": kernel_image_dir,
        }
        if has_reproducer
        else {}
    )

    pois = []
    poi_report_data = None
    pov_report_data = None
    if not report_yaml:
        if not raw_report:
            raise ValueError("You must provide a report to start patching")
        report_yaml = "poi.yaml"
        with open(raw_report, "r") as f:
            pov_report_data = f.read()
        report_analyzer = ReportAnalyzer(pov_report_data)
        poi_report_data = report_analyzer.pois_to_aicc_format()
    if not poi_report_data:
        with open(report_yaml, "r") as f:
            poi_report_data = yaml.safe_load(f)

    # parse the report data
    src_root, filetype, harness_name, harness_id, src_name, tmp_patch_path, invalid_poi_idxs, fallback_poi = _parser_poi_report_data(
        poi_report_data, target_root, commit=crashing_commit
    )

    if raw_report:
        try:
            pov_report = yaml.safe_load(open(raw_report))
            parsed = pov_report.get("run_pov_result").get("pov").get("parser")
            pov_key = parsed if parsed else "unparsed"
            reports = pov_report.get("run_pov_result").get("pov").get(pov_key).get("reports")

            with open(os.path.join(target_root, "project.yaml"), "r") as f:
                sanitizers = yaml.safe_load(f).get("sanitizers")
            for report in reports:
                sanitizer_ids = report.get("triggered_sanitizers")
                if any(
                    [
                        si
                        for si in sanitizer_ids
                        if sanitizers[si] == sanitizer_string or sanitizers[si] in sanitizer_string
                    ]
                ):
                    pov_report_data = report.get("report")
                    break
        except yaml.YAMLError:
            with open(raw_report, "r") as f:
                pov_report_data = f.read()

    for i, poi_data in enumerate(poi_report_data["pois"]):
        if i in invalid_poi_idxs:
            continue

        source_location = poi_data.get("source_location", None)
        poi_src_abs_path = None
        # parse the POI data as if it was from the POI-guy report format
        global_variables = []
        func_src = None
        func_startline = None
        func_endline = None
        if source_location is not None:
            if not source_location.get("key_index"):
                continue
            line_number = int(source_location["line_number"])
            linetext = source_location.get("line_text", None)
            poi_src_relative_path = source_location["relative_file_path"]
            function_name = None
            # some pois have the actual function name
            if "func_name" in source_location:
                function_name = source_location["func_name"]

            # if we have a function indices file, use that, its faster
            if function_index is not None:
                src_key_idx = source_location["key_index"]
                function_index_path = function_index.get(src_key_idx, "")
                if function_index_path == "":
                    continue
                function_info_file = os.path.join(function_json_dir, function_index_path)
                function_info = json.loads(Path(function_info_file).read_text())
                function_name = function_info["funcname"]
                global_variables_dict = function_info.get("global_variables", [])
                for g_dict in global_variables_dict:
                    global_variables.append(g_dict.get("declaration", ""))
                func_startline = function_info.get("start_line")
                func_endline = function_info.get("end_line")
                func_src_backup = function_info.get("code")
                poi_src_abs_path = target_root / "src" / poi_src_relative_path
                func_src = read_src_from_file(poi_src_abs_path, func_startline, func_endline, backup_code=func_src_backup)
            # if we have no function indices file, we have to search for the function name using live POI data
            elif function_name is None:
                poi_src_abs_path = target_root / "src" / poi_src_relative_path
                code_parser = CodeParser(poi_src_abs_path)
                if "function" in source_location:
                    function_name = source_location["function_name"]
                else:
                    function_name = code_parser.function_containing_line(line_number)
        # else if the pois report is directly generated by report parser in PatcherY
        else:
            function_name = poi_data["function"]
            poi_src_relative_path = poi_data["relative_file_path"]
            line_number = poi_data["line_number"]

        # sanity check about relative path
        if poi_src_abs_path is None:
            poi_src_abs_path = target_root / "src" / poi_src_relative_path
            if poi_src_abs_path is None:
                _l.warning(f"Could not find the source file of the POI: {poi_src_relative_path}, skipping...")
                continue

        pois.append(
            ProgramPOI(
                poi_src_abs_path,
                function_name,
                lineno=int(line_number),
                linetext=linetext,
                report=pov_report_data or str(poi_report_data) or None,
                global_variables=global_variables,
                func_src=func_src,
                func_startline=func_startline,
                func_endline=func_endline,
            )
        )

    # When there is not poi in pois field of poi guy report, we pass a fall_back poi that only has raw_report and pass it to diff parser
    if len(pois) == 0:
        _l.warning(
            "There is no poi in poi report. We are adding a fall back poi and pass it to diff parser to add more pois."
        )
        pois = [
            fallback_poi or ProgramPOI(".", None, lineno=0, report=pov_report_data)
        ]

    # for each poi, add debug_info if debug report is provided, pattern match only based on func name.
    if debug_report_data:
        for poi in pois:
            try:  # in case debug_report_data is broken or does not have debug_trace
                for trace in debug_report_data["debug_trace"]:
                    frame = trace["frame"]
                    # _l.debug(f"Function: {frame['function']}")
                    # _l.debug(f"poi.function: {poi.function}")
                    if frame["function"] == poi.function:
                        poi.debug_info = trace["raw"]
                        break
            except KeyError:
                _l.warning("Debug report does not have expected keys. The report might be broken.", exc_info=True)
                exit(1)
            except Exception:
                _l.warning("Debug report is broken and cannot be properly parsed.", exc_info=True)
                exit(1)
    if filetype == "h":
        filetype = "c"
    is_kernel = False

    if (absolute_path_finder(target_root, Path("Kconfig")) is not None) and (
        absolute_path_finder(target_root, Path("Kbuild")) is not None
    ):
        is_kernel = True
        _l.debug(f"🍿 Target is Kernel!")

    patch_generated = generate_patches_from_aicc(
        target_root,
        src_root,
        filetype,
        src_name,
        harness_name,
        sanitizer_string,
        patch_output_dir,
        patch_metadata_output_dir,
        pois=pois,
        alerting_inputs=alerting_inputs,
        benign_inputs=benign_inputs,
        raw_report_data=pov_report_data,
        has_reproducer=has_reproducer,
        kernel_kwargs=kernel_kwargs,
        crashing_commit=crashing_commit,
        invariance_report_data=invariance_report_data,
        indices_by_commit=indices_by_commit,
        changed_func_by_commits=changed_func_by_commit,
        func_indices=function_indices,
        func_json_dir=function_json_dir,
        is_kernel=is_kernel,
        max_attempts=max_attempts,
        max_pois=max_pois,
        harness_id=harness_id,
    )

    return patch_generated


def generate_patches_from_aicc(
    target_root: Path,
    source_root: Path,
    lang: str,
    compile_name: str,
    harness_name: str,
    sanitizer_string: str,
    patch_output_path: Path,
    patch_metadata_output_dir: Path,
    harness_id: Optional[str] = None,
    pois: Optional[list] = None,
    alerting_inputs: list = None,
    benign_inputs: list = None,
    raw_report_data: str = None,
    has_reproducer: bool = False,
    kernel_kwargs: dict = {},
    invariance_report_data: dict = {},
    crashing_commit: str = None,
    indices_by_commit: Path = None,
    changed_func_by_commits: Path = None,
    func_indices: Path = None,
    func_json_dir: Path = None,
    is_kernel: bool = False,
    max_attempts: int = 10,
    max_pois: int = 8
):
    _l.info(f"{len(pois)} PoIs provided for patching attempts, exiting on first patch... ")
    # TODO: handle the case where both pois and original_report are provided

    prog_info = AICCProgramInfo(
        source_root=source_root,
        # TODO: this is bad but it reqs changes everywhere else
        run_script=target_root,
        lang=lang,
        compile_name=compile_name,
        alerting_inputs=alerting_inputs,
        benign_inputs=benign_inputs,
        harness_id=harness_id,
        sanitizer_string=sanitizer_string,
        harness_name=harness_name,
        has_reproducer=has_reproducer,
        is_kernel=is_kernel,
        **kernel_kwargs,
    )
    patcher = Patcher(
        prog_info,
        max_patches=1,
        max_attempts=max_attempts,
        max_pois=max_pois,
        force_llm_report_analysis=lang.lower() == 'java',
        require_invariance=bool(invariance_report_data),
        crashing_commit=crashing_commit,
        indices_by_commit=indices_by_commit,
        changed_func_by_commits=changed_func_by_commits,
        func_indices=func_indices,
        func_json_dir=func_json_dir,
    )
    verified_patches = []
    if patcher.require_invariance:
        invariance_reports = []
        for inv_report_name, inv_report_data in invariance_report_data.items():
            invariance_reports.append(InvarianceReport.from_raw_data(inv_report_data))

        _l.info(f"Found {len(invariance_reports)} invariance reports. Using each for a patching session...")
        for invariance_report in invariance_reports:
            verified_patches = patcher.generate_verified_patches(
                pois=pois, report=raw_report_data, invariance_report=invariance_report
            )
            if verified_patches:
                break
    else:
        verified_patches = patcher.generate_verified_patches(pois=pois, report=raw_report_data)

    if verified_patches:
        # if patch_output_dir is provided, we need to create a temp file to write the patch to
        patch_name = str(uuid.uuid4())
        if patch_output_path is not None:
            patch_output_file = patch_output_path / patch_name
        if patch_metadata_output_dir is not None:
            patch_metadata_output_file = patch_metadata_output_dir / patch_name
        if patch_output_file.exists():
            _l.warning(f"Patch file {patch_output_file} already exists. This may be a bug, run it again!")

        patch = verified_patches[0]
        patch_diff = prog_info.git_diff(patch)
        # write patch diff
        with open(patch_output_file, "w") as f:
            f.write(patch_diff)
        with open(patch_metadata_output_file, "w") as f:
            yaml.safe_dump(
                {"cp_source": compile_name},
                f,
            )
        _l.info(f"💸 The total cost of this patch was {patcher.total_cost} dollars.")
        _l.info(f"Patch metadata is saved to {patch_metadata_output_file}")
        _l.info(f'Verified patch saved to: "{patch_output_file}"')
        return True
    else:
        _l.info(f"💸 We could not make a patch. The total cost was {patcher.total_cost} dollars.")
        _l.error("Failed to generate any verified patches.")
        return False


if __name__ == "__main__":
    main()
