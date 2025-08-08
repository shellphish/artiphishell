"""A class to interact with the analysis graph database."""

import os
from neomodel import db
from pathlib import Path
from loguru import logger
from unidiff import PatchSet, PatchedFile
from binascii import unhexlify
from collections import defaultdict
from subprocess import run, PIPE

from shellphish_crs_utils.models.oss_fuzz import LanguageEnum
from analysis_graph.models.harness_inputs import HarnessInputNode


def get_diff_contents(
    modified_source: Path,
    reset: bool = False,
) -> str:
    """
    Get the diff contents between the original and modified source files.

    Args:
        modified_source (Path): The path to the modified source directory.
        reset (bool): If True, reset the git repository after getting the diff.

    Returns:
        str: The diff contents.
    """
    logger.debug(f"Getting diff contents from directory {modified_source}")
    cur_dir = os.getcwd()
    os.chdir(modified_source)
    result = run(
        ["git", "diff", "--ignore-space-at-eol"], stdout=PIPE, stderr=PIPE, text=True
    )
    if reset:
        run(["git", "stash"], stdout=PIPE, stderr=PIPE, text=True, check=False)
    os.chdir(cur_dir)
    if result.returncode != 0:
        raise RuntimeError(
            f"Git Diff command failed: {result.stderr} {result.returncode}"
        )
    return result.stdout


def apply_diff(
    modified_source: Path, patch_path: Path, allow_rejections: bool = False
) -> None:
    """
    Apply a patch to the modified source directory.

    Args:
        modified_source (Path): The path to the modified source directory.
        patch_path (Path): The path to the patch file.
    """
    logger.debug("Applying patch %s to directory %s" % (patch_path, modified_source))
    cur_dir = os.getcwd()
    os.chdir(modified_source)
    if allow_rejections:
        result = run(
            ["git", "apply", "--reject", str(patch_path)],
            stdout=PIPE,
            stderr=PIPE,
            text=True,
            check=False,
        )
    else:
        result = run(
            ["git", "apply", str(patch_path)], stdout=PIPE, stderr=PIPE, text=True
        )
    os.chdir(cur_dir)
    if result.returncode != 0:
        logger.warning(f"Git apply failed")
        if allow_rejections:
            return
        raise RuntimeError(
            f"Git Apply command failed: {result.stderr} {result.returncode}"
        )


def apply_reverse_diff(
    modified_source: Path, patch_path: Path, allow_rejections: bool = False
) -> None:
    """
    Apply a reverse patch to the modified source directory.

    Args:
        modified_source (Path): The path to the modified source directory.
        patch_path (Path): The path to the patch file.
    """
    logger.debug(
        "Applying reverse patch %s to directory %s" % (patch_path, modified_source)
    )
    cur_dir = os.getcwd()
    os.chdir(modified_source)
    if allow_rejections:
        result = run(
            ["git", "apply", "--reverse", "--reject", str(patch_path)],
            stdout=PIPE,
            stderr=PIPE,
            text=True,
            check=False,
        )
    else:
        result = run(
            ["git", "apply", "--reverse", str(patch_path)],
            stdout=PIPE,
            stderr=PIPE,
            text=True,
        )
    os.chdir(cur_dir)
    if result.returncode != 0:
        logger.warning("Git apply reverse failed")
        if allow_rejections:
            return
        raise RuntimeError(
            f"Git Apply command failed: {result.stderr} {result.returncode}"
        )


def verify_diff_contents(diff_file: Path, original_source: Path) -> str:
    """Verify the diff contents against the modified source directory.

    Args:
        diff_file (Path): The diff file to apply.
        original_source (Path): The path to the original source directory.

    Returns:
        str: The verified diff contents.
    """
    apply_diff(original_source, diff_file, allow_rejections=True)
    new_diff_contents = get_diff_contents(original_source, reset=True)
    patchset = PatchSet.from_string(new_diff_contents)
    for patch in patchset:
        new_hunks = []
        for hunk in patch:
            adds_brace = any(
                line.line_type == "+" and ("{" in line.value or "}" in line.value)
                for line in hunk
            )
            removes_brace = any(
                line.line_type == "-" and ("{" in line.value or "}" in line.value)
                for line in hunk
            )
            if not adds_brace and not removes_brace:
                new_hunks.append(hunk)
        patch[:] = new_hunks
        if len(patch) == 0:
            patchset.remove(patch)

    return str(patchset)


def extract_hunk_from_patch(patch_path: Path, file_name: str, line_num: int) -> str:
    """
    Extract a hunk from a patch file based on the file name and line number.

    Args:
        patch_path (Path): The path to the patch file.
        file_name (str): The name of the file to extract the hunk from.
        line_num (int): The line number to extract the hunk from.

    Returns:
        str: The extracted hunk as a string.
    """
    patchset = PatchSet.from_filename(patch_path)
    for patch in patchset:
        if file_name in patch.path:
            for hunk in patch:
                if (
                    hunk.target_start
                    <= line_num
                    <= hunk.target_start + hunk.target_length
                ):
                    new_patch = PatchedFile(
                        patch.patch_info,
                        patch.source_file,
                        patch.target_file,
                        None,
                        None,
                    )
                    new_patch.append(hunk)
                    return str(new_patch)
    return ""


def do_query(query: str, params: dict = None, retry_limit: int = 5) -> list:
    """
    Execute a Cypher query against the analysis graph database.

    Args:
        query (str): The Cypher query to execute.
        params (dict, optional): Parameters for the query.

    Returns:
        list: The results of the query.
    """
    logger.debug(f"Executing query: {query} with params: {params}")
    results = None
    for _ in range(retry_limit):
        try:
            results, _ = db.cypher_query(query=query, params=params)
            break
        except TimeoutError as e:
            logger.warning(f"Query timed out: {e}. Retrying...")
            continue
        except Exception as e:
            logger.error(f"Query failed: {e}. Retrying...")
            continue
    return results


def verify_func_index_in_ag(funcindex: str) -> bool:
    """
    Verify that the given function index exists in the analysis graph.
    """
    logger.debug(f"Verifying function index {funcindex} in analysis graph")
    query = """
        MATCH (f:CFGFunction {identifier: $funcindex})
        RETURN COUNT(f) > 0
        """
    params = {
        "funcindex": funcindex,
    }

    results = do_query(query=query, params=params)
    try:
        resp = results[0][0]
    except IndexError:
        resp = False
    return resp


def check_function_covered(sink_funcindex: str) -> bool:
    """
    A function that checks if a given sink function index is covered.
    """
    logger.debug(f"Checking if function {sink_funcindex} is covered in analysis graph")
    query = """
        MATCH (f:CFGFunction {identifier: $sink_funcindex})
        MATCH (f)<-[:COVERS]-(:HarnessInputNode)
        RETURN COUNT(f) > 0 AS covered
    """
    params = {
        "sink_funcindex": sink_funcindex,
    }

    results = do_query(query=query, params=params)

    try:
        resp = results[0][0]
    except IndexError:
        resp = False

    return resp


def get_harness_name_and_inputs(sink_funcindex: str) -> dict[str, list[bytes]]:
    """
    A function that gets the harness name and inputs for a given sink function index.
    """
    logger.debug(
        f"Getting harness name and inputs for function {sink_funcindex} in analysis graph"
    )
    query = """
        MATCH (h:HarnessInputNode)-[:COVERS]->(f:CFGFunction {identifier: $sink_funcindex})
        RETURN h
    """
    params = {
        "sink_funcindex": sink_funcindex,
    }

    results = do_query(query=query, params=params)

    if not results or len(results) == 0 or len(results[0]) == 0:
        return None, None

    ret = defaultdict(list)

    harness_input_node: HarnessInputNode
    for harness_input_node in results[0]:
        ret[harness_input_node["harness_name"]].append(
            unhexlify(harness_input_node["content_hex"])
        )

    return ret


def find_closest_covered_caller(sink_funcindex: str) -> tuple[str, list]:
    """
    A function that finds the closest covered caller to a given sink function index.
    """
    logger.debug(
        f"Finding closest covered caller for function {sink_funcindex} in analysis graph"
    )
    # Currently using max recursion depth of 5
    # Reduce this to improve performance
    query = """
        MATCH (end:CFGFunction {identifier: $sink_funcindex})
        MATCH p=(caller:CFGFunction)-[:DIRECTLY_CALLS|MAYBE_INDIRECT_CALLS*1..5]->(end)
        WHERE (caller)<-[:COVERS]-(:HarnessInputNode)
        WITH p, length(p) AS path_len
        ORDER BY path_len ASC
        LIMIT 1
        RETURN p 
    """
    params = {
        "sink_funcindex": sink_funcindex,
    }

    results = do_query(query=query, params=params)

    if not results or len(results) == 0 or len(results[0]) == 0:
        return None, None

    cfg_path = results[0][0]
    assert cfg_path.nodes[-1]["identifier"] == sink_funcindex

    closest_caller = cfg_path.nodes[0]
    call_path = cfg_path.nodes[:-1]

    return closest_caller.get("identifier", None), call_path


def find_paths_to_sink(
    sink_funcindex: str,
    harness_name: str = None,
    source_funcindex: str = None,
    max_depth: int = -1,
    limit: int = 3,
) -> list:
    """
    A function that finds the closest uncovered caller to a given sink function index.
    """
    logger.debug(f"Finding paths to sink function {sink_funcindex} in analysis graph")
    # Currently using max recursion depth of 5
    # Reduce this to improve performance
    if not source_funcindex:
        language = os.getenv("LANGUAGE")
        if language in [
            LanguageEnum.c.value,
            LanguageEnum.cpp.value,
        ]:
            source_funcindex = "LLVMFuzzerTestOneInput"
        elif language == LanguageEnum.jvm:
            source_funcindex = "fuzzerTestOneInput"
        else:
            raise NotImplementedError(f"Not implemented for language {language}")

    if max_depth == -1:
        max_depth = 5

    if harness_name:
        query = f"""
            MATCH (start:CFGFunction) WHERE start.identifier CONTAINS $harness_name AND start.identifier CONTAINS $source_funcindex
            WITH start MATCH (end:CFGFunction) WHERE end.identifier = $sink_funcindex
            WITH start, end MATCH p=(start)-[:DIRECTLY_CALLS|MAYBE_INDIRECT_CALLS*..{max_depth}]->(end)
            RETURN DISTINCT p LIMIT $limit
        """
    else:
        query = f"""
            MATCH (start:CFGFunction) WHERE start.identifier CONTAINS $source_funcindex
            WITH start MATCH (end:CFGFunction) WHERE end.identifier = $sink_funcindex
            WITH start, end MATCH p=(start)-[:DIRECTLY_CALLS|MAYBE_INDIRECT_CALLS*..{max_depth}]->(end)
            RETURN DISTINCT p LIMIT $limit
        """

    params = {
        "source_funcindex": source_funcindex,
        "sink_funcindex": sink_funcindex,
        "limit": limit,
    }

    logger.debug(
        "Finding paths from %s to sink function %s with max depth %d",
        source_funcindex,
        sink_funcindex,
        max_depth,
    )
    results = do_query(query=query, params=params)

    if not results or len(results) == 0 or len(results[0]) == 0:
        logger.debug(
            f"No paths found to sink function {sink_funcindex} with max depth {max_depth}, doubling max depth"
        )
        query = query.replace(str(max_depth), str(max_depth * 2))
        results = do_query(query=query, params=params)

    if not results or len(results) == 0 or len(results[0]) == 0:
        if harness_name:
            query = f"""
                MATCH (start:CFGFunction) WHERE start.identifier CONTAINS $harness_name
                WITH start MATCH (end:CFGFunction) WHERE end.identifier = $sink_funcindex
                WITH start, end MATCH p=(start)-[:DIRECTLY_CALLS|MAYBE_INDIRECT_CALLS*..{max_depth * 2}]->(end)
                ORDER BY length(p) DESC
                RETURN DISTINCT p
                LIMIT $limit
            """
        else:
            query = f"""
                MATCH (end:CFGFunction)
                WHERE end.identifier = $sink_funcindex
                MATCH p = (start:CFGFunction)-[:DIRECTLY_CALLS|MAYBE_INDIRECT_CALLS*..{max_depth * 2}]->(end)
                ORDER BY length(p) DESC
                RETURN DISTINCT p
                LIMIT $limit
            """

        logger.debug(
            "Finding longest paths to sink function %s with max depth %d",
            sink_funcindex,
            max_depth * 2,
        )
        results = do_query(query=query, params=params)

    if not results or len(results) == 0 or len(results[0]) == 0:
        logger.warning(
            f"🫠 No paths found to sink function {sink_funcindex}. Giving up"
        )
        return list()

    all_nodes = set()
    for path in results[0]:
        assert path.nodes[-1]["identifier"] == sink_funcindex, f"Invalid path: {path}"
        # heck it, we're adding the sink_funcindex node as well to the list of nodes
        all_nodes.update(path.nodes)

    # Apparently this might contain None
    all_nodes.discard(None)

    logger.success(f"Found {len(all_nodes)} nodes that can reach {sink_funcindex}")
    return list(all_nodes)


def test_utils_stuff(full_function_indices: Path, target_functions_json_dir: Path):
    sink_funcindex = "/src/nginx/src/os/unix/ngx_linux_sendfile_chain.c:49:1::int ngx_sendfile_r(int *, int *, int)"
    setup_func_resolver(full_function_indices, target_functions_json_dir)
    fixed_sink_funcindex = funcindex_to_ag_funcindex(sink_funcindex)
    foo = check_function_covered(fixed_sink_funcindex)
    bar, _ = find_closest_covered_caller(fixed_sink_funcindex)
    cute = get_harness_name_and_inputs(bar)
    print(cute)


if __name__ == "__main__":
    import sys

    _, full_function_indices, target_functions_json_dir = sys.argv
    test_utils_stuff(Path(full_function_indices), Path(target_functions_json_dir))
