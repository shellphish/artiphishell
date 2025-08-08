import hashlib
import json
import logging
import tempfile
import os
from functools import lru_cache
from multiprocessing import cpu_count
from pathlib import Path
from typing import Dict, List

import clang.cindex
import joblib
from clang.cindex import CursorKind as CK
from joblib import Parallel, delayed

from .defs import VALID_SOURCE_FILE_SUFFIXES_C, WORKDIR, WORKDIR_CLEAN
from .target_info import is_target_path_irrelevant
from .utils import resolve_output_file, safe_decode

logging.basicConfig(level="INFO", format="%(message)s", datefmt="[%X]")
log = logging.getLogger("clang_indexer")
clang.cindex.Config.set_library_file("/usr/lib/x86_64-linux-gnu/libclang-18.so.18")

lib = clang.cindex.conf.lib

def get_full_qualified_name(c: clang.cindex.Cursor, fpath: Path = None) -> str:
    name = c.spelling

    while c.kind != CK.TRANSLATION_UNIT:
        pc = c.semantic_parent

        match pc.kind:
            case (
                CK.TRANSLATION_UNIT
                | CK.UNEXPOSED_DECL
                | CK.FUNCTION_DECL
                | CK.UNION_DECL
            ):
                break

            case CK.LINKAGE_SPEC:
                pass

            case (
                CK.NAMESPACE
                | CK.STRUCT_DECL
                | CK.CLASS_DECL
                | CK.CLASS_TEMPLATE
                | CK.CXX_METHOD
                | CK.CLASS_TEMPLATE_PARTIAL_SPECIALIZATION
            ):
                if pc.is_anonymous():
                    name = f"<anonymous-{fpath.name}-{c.extent.start.line}:{c.extent.start.column}>::{name}"
                else:
                    name = f"{pc.spelling}::{name}"

            case CK.FUNCTION_TEMPLATE:
                name = f"{pc.spelling}::<inner_struc>::{name}"

            case _:
                log.error(
                    f"Unknown cursor kind: {pc.kind} in {pc.spelling} with name {name} "
                    f"in file {fpath}:{c.extent.start.line}-{c.extent.end.line}"
                )
                pass

        c = pc

    return name


def get_func_calls(c: clang.cindex.Cursor):
    calls = []

    for x in c.walk_preorder():
        if x.kind != CK.CALL_EXPR:
            continue

        func_name = x.spelling
        if not func_name:
            srcfile = x.location.file.name
            start, end = x.extent.start.offset, x.extent.end.offset
            contents = safe_decode(Path(srcfile).read_bytes())
            func_name = contents[start:end].split("(")[0]  # FIXME: is this correct?

        children = list(x.get_children())
        call_type = (
            "CXX_METHOD"
            if (children and children[0].kind == CK.MEMBER_REF_EXPR)
            else "FUNCTION"
        )

        calls.append(
            {
                "unique_identifier": x.get_usr(),
                "type": call_type,
                "name": func_name,
            }
        )

    return calls


@lru_cache(maxsize=256)
def _get_extent(fpath: Path, soff: int, eoff: int) -> str:
    fpath = Path(fpath)
    with fpath.open("rb") as f:
        f.seek(soff)
        code = f.read(eoff - soff)
    return safe_decode(code)


def get_extent(
    fpath: Path, cursor: clang.cindex.Cursor, was_directly_compiled: bool
) -> str:
    start_line = cursor.extent.start.line
    end_line = cursor.extent.end.line
    start_offset = cursor.extent.start.offset
    end_offset = cursor.extent.end.offset
    if end_line - start_line > 200:
        # if there's more than 200 lines, be a bit suspicious and check the child elements to make sure it's not an incorrect extend
        last_child = None
        max_line = None
        for child in cursor.walk_preorder():
            if child == cursor:
                continue
            if child.kind in (
                CK.COMPOUND_STMT,
                CK.FUNCTION_DECL,
            ):
                continue  # those tend to be the ones that have messed up ranges, ignore them in this calculation.
            if child.extent.start.file != cursor.extent.start.file:
                continue
            if (
                (child.extent.start.line > 0)
                and (child.extent.end.line > 0)
                and (
                    child.extent.start.line < start_line
                    or child.extent.end.line > end_line
                )
            ):
                log.error(
                    "Child element %s has an extent that is not within the parent element %s: %s not in %s",
                    child.spelling,
                    cursor.spelling,
                    child.extent,
                    cursor.extent,
                )
                continue
            if last_child is None or child.extent.end.line > max_line:
                last_child = child
                max_line = child.extent.end.line

        if last_child is not None and max_line + 100 < end_line:
            # if this was actually compiled and has compile args, the compilation should have succeeded. in that case, error and die.
            # otherwise, this could just be missing if-defs or something like that, just warn and continue
            (log.error if was_directly_compiled else log.warning)(
                "The parent element %s has an extent that is too large: %s, but the largest child element %s has a smaller extent: %s",
                cursor.spelling,
                cursor.extent,
                f"{last_child.kind}: {last_child.spelling}",
                last_child.extent,
            )

    return _get_extent(fpath, start_offset, end_offset)


CACHED_GLOBALS = {}


def return_cached_global(cursor: clang.cindex.Cursor, was_directly_compiled: bool):
    assert cursor.kind == CK.VAR_DECL
    if cursor.semantic_parent.kind in (
        CK.TRANSLATION_UNIT,
        CK.UNEXPOSED_DECL,
    ):
        CACHED_GLOBALS[cursor.get_usr()] = {
            "name": cursor.spelling,
            "type": cursor.type.spelling,
            "declaration_start_line": cursor.extent.start.line,
            "declaration_start_column": cursor.extent.start.column,
            "declaration_start_offset": cursor.extent.start.offset,
            "declaration_end_line": cursor.extent.end.line,
            "declaration_end_column": cursor.extent.end.column,
            "declaration_end_offset": cursor.extent.end.offset,
            "declaration": get_extent(
                cursor.location.file.name,
                cursor,
                was_directly_compiled=was_directly_compiled,
            ),
            "raw_comment": cursor.raw_comment,
            "unique_identifier": cursor.get_usr(),
        }
    return CACHED_GLOBALS.get(cursor.get_usr(), None)


def return_referenced_global(cursor: clang.cindex.Cursor, was_directly_compiled: bool):
    assert cursor.kind in (
        CK.DECL_REF_EXPR,
        CK.MEMBER_REF_EXPR,
    )
    token = cursor.get_definition()
    if not token:
        token = cursor.referenced
    if not token:
        return None
    # check if this is a global variable
    if token.kind != CK.VAR_DECL:
        return None

    return return_cached_global(token, was_directly_compiled=was_directly_compiled)


class ClangIndexer:
    def __init__(
        self,
        output: Path,
        threads: int = -1,
        compile_args: Path = None,
    ):
        self.output = output
        self.session = None
        self.repo = None
        self.num_procs = int(os.environ.get("NPROC_VAL", cpu_count()))
        self.threads = threads if threads != -1 else self.num_procs
        self.compile_args = compile_args or []

        self.output.mkdir(parents=True, exist_ok=True)
        self.function_dir = None
        self.method_dir = None
        self.macro_dir = None

    def save_info(self, info):
        if not info:
            return

        entry = {
            "target_compile_args": info["target_compile_args"],
            "was_directly_compiled": info["was_directly_compiled"],
            "hash": info["hash"],
            "code": info["code"],
            "signature": info["signature"],
            "filename": Path(info["target_container_path"]).name,
            "cfg": "",  # TODO: Fix
            "start_line": info["start_line"],
            "start_column": info["start_column"],
            "start_offset": info["start_offset"],
            "end_line": info["end_line"],
            "end_column": info["end_column"],
            "end_offset": info["end_offset"],
            "global_variables": info["global_variables"],
            "local_variables": [],  # TODO: Fix
            "arguments": [],  # TODO: Fix
            "func_return_type": "",
            "is_generated_during_build": info["is_generated_during_build"],
            "focus_repo_relative_path": info["focus_repo_relative_path"],
            "target_container_path": info["target_container_path"],
            "unique_identifier": info["unique_identifier"],
            "raw_comment": info["raw_comment"],
            "func_calls_in_func_with_fullname": [],
        }

        if info["_info_type"] == "function":
            outdir = self.function_dir
            entry.update(
                {
                    "funcname": info["name"],
                    "full_funcname": info["name"],
                    "func_return_type": info["func_return_type"],
                    "func_calls_in_func_with_fullname": [
                        {"name": call["name"], "type": call["type"]}
                        for call in info["calls"]
                    ],
                    "comments": [info["comment"]] if info["comment"] else [],
                }
            )

        elif info["_info_type"] == "method":
            outdir = self.method_dir
            entry.update(
                {
                    "funcname": info["method_name"],
                    "full_funcname": info["full_name"],
                    "func_calls_in_func_with_fullname": [
                        {"name": call["name"], "type": call["type"]}
                        for call in info["calls"]
                    ],
                    "comments": [info["comment"]] if info["comment"] else [],
                }
            )

        elif info["_info_type"] == "macro":
            outdir = self.macro_dir
            entry.update(
                {
                    "funcname": info["name"],
                    "full_funcname": info["name"],
                }
            )
        else:
            raise Exception("Unknown info type")

        outdir.mkdir(parents=True, exist_ok=True)

        try:
            funcname_on_path = entry["funcname"]
            funcname_on_path = funcname_on_path.split("::")[-1]
            funcname_on_path = funcname_on_path.split("<")[0]
            
            save_path = (
                outdir
                / f"{funcname_on_path}_{entry['filename']}_{info['hash']}.json".replace(
                    "/", "-"
                )
            )
            if save_path.exists():
                log.debug(f"Skipping saving {save_path} as it already exists.")
            else:
                # this could still race cond, but the file won't be corrupted, just overwritten
                self.atomic_file_write(save_path, json.dumps(entry, indent=4, default=str))
        except Exception as e:
            log.error(f"Error saving:\n{entry}\n\n{e}")

    def atomic_file_write(self, path: Path, data: str):
        path = Path(path)
        with tempfile.NamedTemporaryFile(
            mode='w',
            dir=path.parent,
            suffix='.tmp',
            delete=False
        ) as temp_file:
            temp_path = Path(temp_file.name)
            try:
                temp_file.write(data)
                temp_file.flush()
                os.fsync(temp_file.fileno())
                temp_path.replace(path)
            except Exception:
                temp_path.unlink(missing_ok=True)
                raise

    @staticmethod
    def get_referenced_globals(
        cursor: clang.cindex.Cursor,
        was_directly_compiled: bool = False,
    ):
        out_variables = []
        for sub_expr in cursor.walk_preorder():
            if "REF" not in sub_expr.kind.name or "EXPR" not in sub_expr.kind.name:
                continue
            if sub_expr.kind in (CK.MEMBER_REF_EXPR,):
                # this is a member reference, we already have the global variable
                continue
            if sub_expr.kind in (CK.DECL_REF_EXPR,):
                if global_var := return_referenced_global(
                    sub_expr, was_directly_compiled=was_directly_compiled
                ):
                    out_variables.append(global_var)
            else:
                log.error(
                    "Unknown cursor kind when processing function names: %s in %s in file %s:%d-%d",
                    sub_expr.kind,
                    sub_expr.spelling,
                    sub_expr.location.file.name,
                    sub_expr.extent.start.line,
                    sub_expr.extent.end.line,
                    extra={
                        "crs.action.code.file": str(sub_expr.location.file.name),
                        "crs.action.code.container_path": str(
                            sub_expr.location.file.name
                        ),
                    },
                )
                continue
        return out_variables

    def _process_macro(
        self, c, fpath: Path, compile_args: List[str], original_compile_args: Dict
    ):
        if not lib.clang_Cursor_isMacroFunctionLike(c):
            return None
        tokens = list(c.get_tokens()) # MACRO_NAME ( ARGS ) ...
        assert tokens

        if len(tokens) < 2 or tokens[1].spelling != "(" or tokens[0].spelling != c.spelling:
            return None

        signature = None
        for i, token in enumerate(tokens[2:], 2):
            if token.spelling == ')':
                signature = f"{c.spelling}({''.join(t.spelling for t in tokens[2:i])})"
                break

        name = c.spelling

        start_line = c.extent.start.line
        end_line = c.extent.end.line
        code = get_extent(fpath, c, was_directly_compiled=len(compile_args) > 0)
        g_vars = ClangIndexer.get_referenced_globals(c)
        h = (
            hashlib.md5(f"{code}|{g_vars}|{fpath}".encode())
            .digest()
            .hex()
        )
        assert c.get_usr() is not None, (
            f"c.get_usr() is None for {c.spelling} in {fpath}:{start_line}-{end_line}"
        )
        info = {
            "_info_type": "macro",
            "target_compile_args": original_compile_args,
            "was_directly_compiled": len(compile_args) > 0,
            "unique_identifier": c.get_usr(),
            "raw_comment": c.raw_comment,
            "hash": h,
            "name": name,
            "signature": signature,
            "is_generated_during_build": fpath.is_relative_to(WORKDIR)
            and not (WORKDIR_CLEAN / fpath.relative_to(WORKDIR)).exists(),
            "focus_repo_relative_path": fpath.relative_to(WORKDIR)
            if fpath.is_relative_to(WORKDIR)
            else None,
            "target_container_path": fpath,
            "code": code,
            "start_line": start_line,
            "start_column": c.extent.start.column,
            "start_offset": c.extent.start.offset,
            "end_line": end_line,
            "end_column": c.extent.end.column,
            "end_offset": c.extent.end.offset,
            "global_variables": g_vars,
        }
        return info

    def _process_function(
        self, c, fpath: Path, compile_args: List[str], original_compile_args: Dict
    ):
        name = get_full_qualified_name(c, fpath=fpath)
        src_file = fpath
        signature = c.result_type.spelling + " " + c.displayname

        start_line = c.extent.start.line
        end_line = c.extent.end.line
        code = get_extent(src_file, c, was_directly_compiled=len(compile_args) > 0)
        g_vars = ClangIndexer.get_referenced_globals(c)
        h = (
            hashlib.md5(f"{code}|{g_vars}|{fpath}".encode())
            .digest()
            .hex()
        )
        assert c.get_usr() is not None, (
            f"c.get_usr() is None for {c.spelling} in {fpath}:{start_line}-{end_line}"
        )

        info = {
            "_info_type": "function",
            "target_compile_args": original_compile_args,
            "was_directly_compiled": len(compile_args) > 0,
            "unique_identifier": c.get_usr(),
            "raw_comment": c.raw_comment,
            "hash": h,
            "name": name,
            "mangled_name": c.mangled_name,
            "is_generated_during_build": fpath.is_relative_to(WORKDIR)
            and not (WORKDIR_CLEAN / fpath.relative_to(WORKDIR)).exists(),
            "focus_repo_relative_path": fpath.relative_to(WORKDIR)
            if fpath.is_relative_to(WORKDIR)
            else None,
            "target_container_path": fpath,
            "signature": signature,
            "code": code,
            "comment": c.raw_comment,
            "calls": get_func_calls(c),
            "start_line": start_line,
            "start_column": c.extent.start.column,
            "start_offset": c.extent.start.offset,
            "end_line": end_line,
            "end_column": c.extent.end.column,
            "end_offset": c.extent.end.offset,
            "global_variables": g_vars,
            "func_return_type": c.result_type.spelling,
        }
        return info

    def _process_method(
        self, c, fpath: Path, compile_args: List[str], original_compile_args: Dict
    ):
        full_name = get_full_qualified_name(c, fpath=fpath)
        assert "::" in full_name, (
            f"Method {c.spelling} in {fpath} has no namespace or class: {full_name}"
        )

        name_parts = full_name.split("::")
        last_anon_idx = next((i for i, p in reversed(list(enumerate(name_parts))) if p.startswith("<")), -1)
        method_name = "::".join(name_parts[last_anon_idx + 1:])

        signature = c.result_type.spelling + " " + c.displayname

        start_line = c.extent.start.line
        end_line = c.extent.end.line
        code = get_extent(fpath, c, was_directly_compiled=len(compile_args) > 0)
        g_vars = ClangIndexer.get_referenced_globals(c)
        h = (
            hashlib.md5(f"{code}|{g_vars}|{fpath}".encode())
            .digest()
            .hex()
        )
        assert c.get_usr() is not None, (
            f"c.get_usr() is None for {c.spelling} in {fpath}:{start_line}-{end_line}"
        )
        info = {
            "_info_type": "method",
            "target_compile_args": original_compile_args,
            "was_directly_compiled": len(compile_args) > 0,
            "unique_identifier": c.get_usr(),
            "raw_comment": c.raw_comment,
            "hash": h,
            "full_name": full_name,
            "method_name": method_name,
            "mangled_name": c.mangled_name,
            "is_generated_during_build": fpath.is_relative_to(WORKDIR)
            and not (WORKDIR_CLEAN / fpath.relative_to(WORKDIR)).exists(),
            "focus_repo_relative_path": fpath.relative_to(WORKDIR)
            if fpath.is_relative_to(WORKDIR)
            else None,
            "target_container_path": fpath,
            "signature": signature,
            "code": code,
            "comment": c.raw_comment,
            "calls": get_func_calls(c),
            "start_line": start_line,
            "start_column": c.extent.start.column,
            "start_offset": c.extent.start.offset,
            "end_line": end_line,
            "end_column": c.extent.end.column,
            "end_offset": c.extent.end.offset,
            "global_variables": g_vars,
        }
        return info

    def _process_file(
        self,
        fpath: Path,
        compile_args: List[str],
        original_compile_args: Dict,
    ):
        """Process file to extract functions, methods, and macros."""

        # Parse file
        index = clang.cindex.Index.create()
        tu = index.parse(
            fpath,
            args=["-fparse-all-comments"] + compile_args,
            options=(
                clang.cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD
                | clang.cindex.TranslationUnit.PARSE_INCOMPLETE
            ),
        )

        # Print diagnostics
        if len(tu.diagnostics) > 0 and len(compile_args) > 0:
            log.warning(
                "Diagnostics while parsing %s with args %s:\n\t%s",
                fpath,
                compile_args,
                "\n\t".join(str(d) for d in tu.diagnostics),
            )

        # Define processor mapping
        processors = {
            CK.MACRO_DEFINITION: self._process_macro,
            CK.FUNCTION_DECL: self._process_function,
            CK.FUNCTION_TEMPLATE: self._process_function,
            CK.CXX_METHOD: self._process_method,
            CK.DESTRUCTOR: self._process_method,
            CK.CONSTRUCTOR: self._process_method,
        }

        # Process cursors
        iterator = tu.cursor.walk_preorder()
        info_list = []
        for c in iterator:
            try:
                if not c.extent.start.file:
                    continue

                if not Path(c.extent.start.file.name).is_relative_to(Path("/src")):
                    continue

                if is_target_path_irrelevant(Path(c.extent.start.file.name), WORKDIR):
                    log.debug(
                        f"Skipping cursor in irrelevant file {c.extent.start.file.name}"
                    )
                    continue

                # for files without compile args, do not process included files
                if not original_compile_args and c.extent.start.file.name != str(
                    fpath.resolve()
                ):
                    continue

                # skip unsupported cursor types
                if c.kind not in processors:
                    continue

                # skip non-defs
                if c.kind != CK.MACRO_DEFINITION and not c.is_definition():
                    continue

                # Process and add to list if result is valid
                if info := processors[c.kind](
                    c,
                    Path(c.extent.start.file.name).resolve(),
                    compile_args,
                    original_compile_args,
                ):
                    info_list.append(info)

            except Exception as e:
                log.error(
                    "Error processing cursor: %s for %s in %s:%d-%d",
                    c,
                    c.spelling,
                    fpath,
                    c.extent.start.line,
                    c.extent.end.line,
                    exc_info=True,
                )
                log.error("Cursor: %s", c)

        return info_list

    def process_file(
        self,
        fpath: Path,
        compile_args: List[str] = None,
        original_compile_args: Dict = None,
    ):
        info_list = []
        try:
            info_list = self._process_file(
                fpath,
                compile_args or [],
                original_compile_args or {},
            )
        except Exception as e:
            log.critical(f"Failed to parse: {fpath} with args: {compile_args}: {e}")
        return info_list

    def process_file_and_save(
        self, fpath: Path, compile_args: List[str], original_compile_args: Dict
    ):
        info_list = self.process_file(fpath, compile_args, original_compile_args)
        for info in info_list:
            self.save_info(info)

    def resolve_compilation_args(self, orig_arg):
        new_arg = dict(orig_arg)
        try:
            # In bear 3.x, paths are always provided as absolute paths
            directory = Path(orig_arg["directory"])
            input_file = Path(orig_arg["file"])
            output_file = Path(orig_arg["output"])
            arguments = orig_arg["arguments"]

            postprocessed_file_args = []
            i = 1  # skip the first argument which is the compiler executable
            while i < len(arguments):
                arg = arguments[i]
                i += 1

                if arg == "-c":
                    continue
                elif arg == "-o":
                    i += 1
                    continue
                if (directory / arg).resolve() == input_file:
                    continue
                if (directory / arg).resolve() == output_file:
                    raise Exception(
                        f"Output file should not be in the compile arguments: {arg=} in {arguments=} should have been filtered by -o"
                    )
                if arg.endswith(".o"):
                    continue
                if arg.endswith(".a"):
                    continue
                if arg.endswith(".so"):
                    continue
                if arg.startswith("-I"):
                    if arg.strip() == "-I":
                        include_path = arguments[i]
                        i += 1
                    else:
                        include_path = arg.split("-I")[1].strip()
                    if not include_path.strip():
                        log.warning("Include path is empty???? Ignore i guess")
                        continue
                    include_path = (directory / include_path).resolve()
                    arg = "-I" + str(include_path)

                postprocessed_file_args.append(arg)

            if (
                "/src/" in postprocessed_file_args
                or any(a.startswith("/out/") for a in postprocessed_file_args)
                or any(a.startswith("/work/") for a in postprocessed_file_args)
            ):
                log.error(
                    "A compile-arg was not symbolized correctly: %s",
                    postprocessed_file_args,
                )

            new_arg["arguments"] = postprocessed_file_args
            return new_arg

        except Exception as e:
            log.error(f"Unable to parse compile arg {orig_arg}: {e}")

    def run(self):
        self.setup_output_dirs()

        tasks = []
        compile_args = json.loads(self.compile_args.read_text())
        resolve_output_file(compile_args)
        args_by_file = dict()
        for orig_arg in compile_args:
            if "output" not in orig_arg:
                log.warning("No output file in compilation arguments: %s", orig_arg)
                continue
            orig_arg.pop("starttime", None)
            new_arg = self.resolve_compilation_args(orig_arg)
            args_by_file[new_arg["file"]] = (orig_arg, new_arg)

        files = {
            file
            for s in VALID_SOURCE_FILE_SUFFIXES_C
            for file in Path("/src").rglob(f"*{s}")
        }

        for f in files:
            if is_target_path_irrelevant(f, WORKDIR):
                log.debug(f"Skipping processing irrelevant file {f}")
                continue
            if (fpath_str := str(f.resolve())) in args_by_file:
                orig_arg, new_arg = args_by_file[fpath_str]
                tasks.append((f, new_arg["arguments"], orig_arg))
            else:
                tasks.append((f, [], {}))

        log.info("Tasks: %s", len(tasks))
        if self.num_procs > 1:
            with joblib.parallel_backend("loky", n_jobs=self.num_procs):
                Parallel(n_jobs=self.threads, verbose=True)(
                    delayed(self.process_file_and_save)(*args) for args in tasks
                )
        else:
            for args in tasks:
                self.process_file_and_save(*args)

        log.info("Done!")

    def setup_output_dirs(self):
        self.output.mkdir(exist_ok=True, parents=True)
        for dir_name in ["FUNCTION", "METHOD", "MACRO"]:
            (self.output / dir_name).mkdir(exist_ok=True, parents=True)

        self.function_dir = self.output / "FUNCTION"
        self.method_dir = self.output / "METHOD"
        self.macro_dir = self.output / "MACRO"
