from collections import defaultdict
import os
import re
import time
from shellphish_crs_utils.models.llvm_symbolizer import (
    parse_llvm_symbolizer_json_output_file,
)
from shellphish_crs_utils.models.oss_fuzz import LanguageEnum
from shellphish_crs_utils.models.symbols import JavaInfo, SourceLocation
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from shellphish_crs_utils.utils import artiphishell_should_fail_on_error
import yaml
import logging
import argparse

from targets import TARGET_IDENTIFIERS
from shellphish_crs_utils.models.oss_fuzz import AugmentedProjectMetadata
from crs_telemetry.utils import (
    init_otel,
    get_otel_tracer,
    status_ok,
)
from pathlib import Path

init_otel("analyze_target", "building", "target_identification")
tracer = get_otel_tracer()

LOG = logging.getLogger("analyze_target")

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)


def identify_targets(target_dir):
    known_applications = defaultdict(list)
    by_extension = defaultdict(list)
    try:
        for root, dirs, files in os.walk(target_dir):
            for target, identifiers in TARGET_IDENTIFIERS.items():
                for identifier in identifiers:
                    try:
                        if res := identifier(root, dirs, files):
                            known_applications[target].append({
                                'relative_path': os.path.relpath(root, target_dir),
                                'metadata': res
                            })
                    except Exception as e:
                        LOG.warning(f"Error identifying target {target} in {root}: {e}", exc_info=True)
                        continue
            if '/.git/' not in root:
                for file in files:
                    ext = file.split('.')[-1] if '.' in file[1:] else ''
                    by_extension[ext].append(os.path.join(root, file))
    except Exception as e:
        LOG.error(f"Error walking directory {target_dir}: {e}", exc_info=True)
        return {'known_sources': {}, 'files_by_type': {}}

    by_type = defaultdict(list)
    for ext, files in by_extension.items():
        if not ext:
            continue
        if ext in ("c", "h"):
            by_type["c"].extend(files)
        elif ext in ("cpp", "cc", "c++", "cxx", "h++", "hpp"):
            by_type["cpp"].extend(files)
        elif ext in ("pem", "crt", "key"):
            by_type["certificates"].extend(files)
        elif ext in ("bazel", "bzl", "bazelrc"):
            by_type["bazel"].extend(files)
        elif ext in ("am", "m4"):
            by_type["autotools"].extend(files)
        elif ext in ("bat",):
            by_type["batch"].extend(files)
        elif ext in ("perl", "pl"):
            by_type["perl"].extend(files)
        elif ext == "java":
            by_type["java"].extend(files)
        elif ext == "py":
            by_type["python"].extend(files)
        elif ext in ("sh",):
            by_type["shell"].extend(files)
        elif ext in ("go",):
            by_type["go"].extend(files)
        elif ext in ("rb",):
            by_type["ruby"].extend(files)
        elif ext in ("js", "ts", "jsx", "tsx"):
            by_type["javascript"].extend(files)
        elif ext in ("html", "xhtml"):
            by_type["html"].extend(files)
        elif ext in ("css",):
            by_type["css"].extend(files)
        elif ext in ("json",):
            by_type["json"].extend(files)
        elif ext in ("yaml", "yml"):
            by_type["yaml"].extend(files)
        elif ext in ("xml",):
            by_type["xml"].extend(files)
        elif ext in ("md",):
            by_type["markdown"].extend(files)
        elif ext in ("sql",):
            by_type["sql"].extend(files)
        elif ext in ("j2", "jinja2"):
            by_type["jinja2"].extend(files)
        elif ext in ("jelly",):
            by_type["jelly"].extend(files)
            # print(f"Jelly files: {files}")
        elif ext in ("l", "y"):
            by_type["lex-yacc"].extend(files)
        elif ext in ("vbs",):
            by_type["vbs"].extend(files)
        elif ext in ("jpg", "jpeg", "png", "gif", "svg", "webp"):
            by_type["images"].extend(files)
        elif ext in ("jar", "war", "ear"):
            by_type["java-archive"].extend(files)
        elif ext in ("zip", "tar", "gz", "bz2", "xz", "7z"):
            by_type["archives"].extend(files)
        elif ext in ("pdf", "doc", "docx", "ppt", "pptx", "xls", "xlsx"):
            by_type["office"].extend(files)
        elif ext in ("txt", "log"):
            by_type["text"].extend(files)
        # else:
        #     print(f"Unknown extension: {ext} in {files}")
        #     by_language['unknown_'+ext].extend(files)

    return {
        "known_sources": known_applications,
        "files_by_type": {
            lang: len(files)
            for lang, files in sorted(by_type.items(), key=lambda x: len(x[1]))
        },
    }

def edit_distance(str1: str, str2: str) -> int:
    """
    Calculate the edit distance between two strings using the Levenshtein distance algorithm.
    """
    if len(str1) < len(str2):
        return edit_distance(str2, str1)

    if len(str2) == 0:
        return len(str1)

    previous_row = range(len(str2) + 1)
    for i, c1 in enumerate(str1):
        current_row = [i + 1]
        for j, c2 in enumerate(str2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def get_harness_source_location(
    oss_fuzz_project: OSSFuzzProject, harness_name: str
) -> SourceLocation:
    if oss_fuzz_project.project_language in [LanguageEnum.c, LanguageEnum.cpp]:
        if harness_name.startswith(
            "/out/"
        ):  # allow giving the specific /out/-specifc path instead of the name too for convenience
            harness_name = harness_name[5:]
        assert "/" not in harness_name, "Harness name should be a name, not a path"
        symbols = parse_llvm_symbolizer_json_output_file(
            oss_fuzz_project.artifacts_dir_out
            / f"{harness_name}.shellphish_harness_symbols.json"
        )

        assert len(symbols) == 1, (
            f"Expected exactly one symbol for harness {harness_name}, found {len(symbols)}: {symbols}"
        )
        (symbol_entry,) = symbols
        bin_loc, source_locs = symbol_entry.get_locations()
        for source_loc in source_locs:
            if source_loc.function_name == "LLVMFuzzerTestOneInput":
                return source_loc
        assert False, (
            f"Could not find the LLVMFuzzerTestOneInput function in the symbol locations for harness {harness_name}"
        )
    elif oss_fuzz_project.project_language in [LanguageEnum.jvm]:
        # open the harness itself
        with open(oss_fuzz_project.artifacts_dir_out / f"{harness_name}", "r") as f:
            harness_wrapper_source = f.read().replace("\n", " ")

        # regex out the --target_class parameter
        # first try: use the --target_class parameter to find the class name
        harness_class = re.search(
            r"--target_class[\s=][\"']?([^ '\"]+)", harness_wrapper_source
        ).group(1)
        harness_path = "/".join(harness_class.split(".")) + ".java"
        possible_sources = list(
            oss_fuzz_project.artifacts_dir_built_src.rglob(harness_path)
        )
        if len(possible_sources) == 1 and b'fuzzerTestOneInput' in possible_sources[0].read_bytes():
            (source_file,) = possible_sources
            relpath = source_file.relative_to(oss_fuzz_project.artifacts_dir_built_src)
            return SourceLocation(
                full_file_path=Path("/src/") / relpath,
                file_name=source_file.name,
                function_name="fuzzerTestOneInput",
                java_info=JavaInfo(
                    class_path=harness_class,
                    class_name=harness_class.rsplit(".", 1)[-1],
                    package=".".join(harness_class.rsplit(".", 1)[:-1]),
                    method_name="fuzzerTestOneInput",
                    full_method_path=harness_class + ".fuzzerTestOneInput",
                    # we can't know the method_descriptor because we don't know whether it's a byte-array harness or a FuzzedDataProvider harness
                ),
            )
        # otherwise, assume it's the <harness_name>.java
        else:
            possible_sources = list(oss_fuzz_project.artifacts_dir_built_src.rglob(f"{harness_name}.java"))
            if len(possible_sources) == 1 and b'fuzzerTestOneInput' in possible_sources[0].read_bytes():
                (source_file,) = possible_sources
                relpath = source_file.relative_to(oss_fuzz_project.artifacts_dir_built_src)
                return SourceLocation(
                    full_file_path=Path("/src/") / relpath,
                    file_name=source_file.name,
                    function_name="fuzzerTestOneInput",
                    java_info=JavaInfo(
                        class_name=harness_class.rsplit(".", 1)[-1],
                        method_name="fuzzerTestOneInput",
                        # we can't know the method_descriptor because we don't know whether it's a byte-array harness or a FuzzedDataProvider harness
                    ),
                )
            else:
                # okay, last ditch effort: find all files containing `fuzzerTestOneInput` and return the one with the smallest
                # edit-distance to the harness name
                all_harness_files = list(
                    oss_fuzz_project.artifacts_dir_built_src.rglob("*.java")
                )
                all_harness_files = [
                    f for f in all_harness_files if b"fuzzerTestOneInput" in f.read_bytes()
                ]
                if len(all_harness_files) == 1:
                    (source_file,) = all_harness_files
                    relpath = source_file.relative_to(oss_fuzz_project.artifacts_dir_built_src)
                    return SourceLocation(
                        full_file_path=Path("/src/") / relpath,
                        file_name=source_file.name,
                        function_name="fuzzerTestOneInput",
                        java_info=JavaInfo(
                            class_name=relpath.name.split(".java")[0],
                            method_name="fuzzerTestOneInput",
                            # we can't know the method_descriptor because we don't know whether it's a byte-array harness or a FuzzedDataProvider harness
                        ),
                    )

                else:
                    # okay, now we really have to do edit-distance of the names
                    all_harness_files = sorted(
                        all_harness_files,
                        key=lambda f: edit_distance(
                            f.name, harness_name
                        ),
                    )
                    if len(all_harness_files) > 0:
                        # okay, just take the one with the lowest edit distance
                        source_file = all_harness_files[0]
                        relpath = source_file.relative_to(oss_fuzz_project.artifacts_dir_built_src)
                        return SourceLocation(
                            full_file_path=Path("/src/") / relpath,
                            file_name=source_file.name,
                            function_name="fuzzerTestOneInput",
                            java_info=JavaInfo(
                                class_name=relpath.name.split(".java")[0],
                                method_name="fuzzerTestOneInput",
                                # we can't know the method_descriptor because we don't know whether it's a byte-array harness or a FuzzedDataProvider harness
                            ),
                        )
                    else:
                        # just can't find it, leave it up to the function resolver, but still return something
                        LOG.error(
                            f"Could not really find the harness source file for {harness_name} in {oss_fuzz_project.artifacts_dir_built_src}"
                        )
                        if artiphishell_should_fail_on_error():
                            raise RuntimeError(
                                f"Could not find the harness source file for {harness_name} in {oss_fuzz_project.artifacts_dir_built_src}"
                            )
                        return SourceLocation(
                            file_name=f'{harness_name}.java',
                            function_name="fuzzerTestOneInput",
                            java_info=JavaInfo(
                                class_name=harness_name,
                                method_name="fuzzerTestOneInput",
                            ),
                        )
        # TODO
        raise NotImplementedError(
            "JVM harness symbol extraction is not yet implemented"
        )
    else:
        assert False, f"Unsupported language {oss_fuzz_project.project_language}"


if __name__ == "__main__":
    with tracer.start_as_current_span("analyze_target") as span:
        parser = argparse.ArgumentParser()
        parser.add_argument("input_metadata_path", type=Path)
        parser.add_argument("canonical_build_artifacts_dir", type=Path)
        parser.add_argument("target_dir", type=str)
        parser.add_argument("output", type=str)
        args = parser.parse_args()

        oss_fuzz_project = OSSFuzzProject(args.canonical_build_artifacts_dir)


        with open(
            args.canonical_build_artifacts_dir
            / "artifacts/out/shellphish_build_metadata.yaml",
            "r",
        ) as f:
            shellphish_build_meta = yaml.safe_load(f)

        with open(args.input_metadata_path, "r") as f:
            project = yaml.safe_load(f)

        LOG.info(f"Analyzing {args.target_dir}")
        if "shellphish" not in project:
            project["shellphish"] = {}

        shellphish_meta_augmented = project['shellphish']
        project['shellphish'].update(shellphish_build_meta)
        try:
            target_identification = identify_targets(args.target_dir)
        except Exception as e:
            LOG.error(f"Error identifying targets in {args.target_dir}: {e}", exc_info=True)
            target_identification = {'known_sources': {}, 'files_by_type': {}}
        project['shellphish'].update(target_identification)
        project['shellphish']['harness_source_locations'] = {
            harness_name: get_harness_source_location(oss_fuzz_project, harness_name)
            for harness_name in shellphish_build_meta['harnesses']
        }
        with open(args.output, 'w') as f:
            # import ipdb; ipdb.set_trace()
            f.write(AugmentedProjectMetadata.model_validate(project).model_dump_json(indent=2))

            LOG.info(f"Analysis saved to {args.output}")
            span.add_event(
                "analyze_target.result",
                {
                    "result": AugmentedProjectMetadata.model_validate(
                        project
                    ).model_dump_json(indent=2)
                },
            )
            span.set_status(status_ok())
