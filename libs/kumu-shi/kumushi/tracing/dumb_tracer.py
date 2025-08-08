import logging
from pathlib import Path

from kumushi.code_parsing import CodeFunction
from kumushi.data import ProgramInput, Program, PoI, PoISource
from kumushi.aixcc import AICCProgram
from collections import defaultdict
import shutil
import re

from kumushi.tracing.abstract_tracer import AbstractTracer

_l = logging.getLogger(__name__)

EXCLUDED_DIRS = {
    # Tests and QA
    "test", "tests", "unittests", "regression", "integration", "e2e", "qa", "spec",

    # Fuzzing
    "fuzz", "fuzzing", "fuzzer", "fuzzers", "oss-fuzz",

    # Benchmarks
    "bench", "benchmarks", "performance", "perf", "profiling",

    # Third-party or external code
    "third_party", "thirdparty", "3rdparty", "external", "deps", "vendor", "contrib", "subprojects", "extern", "external_libs", "vendors",

    # Build and packaging
    "build", "cmake", "autotools", "meson", "configure", "scripts", "makefiles", "toolchain", "packaging", "ci", ".github", ".gitlab", ".circleci", ".buildkite",

    # Coverage and debug
    "coverage", "cov", "gcov", "lcov", "debug",

    # Examples
    "example", "examples", "sample", "samples", "demo", "demos",

    # Misc
    "tools", "script", "scripts", "infra", "maintenance", "tool",
}


class DumbCallTracer(AbstractTracer):
    """
    This is a very simple tracer that works by inserting print statements into the program. Currently, it only
    supports C.
    """
    TRACER_HIT_SYM = "TRACE_HIT"
    TRACER_PRINT_TEMPLATE = "\\nTRACE_HIT|%s|\\n"
    TRACER_REGEX = rb"^TRACE_HIT\|(.*?)\|$"
    TRACE_INSERTS = {
        "c": f'write(2, "{TRACER_PRINT_TEMPLATE}", %s);',
        "jvm": f'System.out.print("{TRACER_PRINT_TEMPLATE}");\n',
    }
    TRACE_INSERTS["cpp"] = TRACE_INSERTS["c"]

    # imports needed for languages
    TRACE_IMPORTS = {"c": "", "jvm": "import java.lang.System;\n"}
    TRACE_IMPORTS["cpp"] = TRACE_IMPORTS["c"]

    # backup insertions (for cursed projects like sqlite)
    C_BACKUP_INSERT = f'fprintf(stderr, "{TRACER_PRINT_TEMPLATE}");\n'

    def __init__(self, program: AICCProgram):
        super().__init__(program)
        self.trace_code_insert = DumbCallTracer.TRACE_INSERTS[program.code.language]
        self.trace_import_insert = DumbCallTracer.TRACE_IMPORTS.get(program.code.language, "")
        self.is_c = "c" in program.code.language.lower()
        self.sorted_functions = self.sort_functions_by_line()
        self._is_sqlite = "sqlite" in str(self.program.target_project.project_name)
        self.write_illegal = self._is_sqlite

    def sort_functions_by_line(self):
        functions_by_file = defaultdict(list)
        functions: list[CodeFunction] = self.program.code.get_functions()
        for function in functions:
            functions_by_file[str(function.file_path)].append(function)

        sorted_functions_by_file = {}
        for filename, functions in functions_by_file.items():
            sorted_functions_by_file[filename] = sorted(functions, key=lambda x: x.start_line)

        return sorted_functions_by_file

    def instrument_functions(self):
        # Process each source file independently.
        inst_count = 0
        for rel_file_path, functions in self.sorted_functions.items():
            rel_file_path = Path(rel_file_path)
            top_dir = rel_file_path.parts[0] if rel_file_path.parts else ""
            if not top_dir:
                continue

            if top_dir in EXCLUDED_DIRS:
                _l.debug("Skipping file %s due to blacklist", rel_file_path)
                continue

            full_path = self.program.source_root / rel_file_path
            try:
                with open(full_path, "r+", encoding="ascii") as source_file:
                    file_lines = source_file.readlines()
            except UnicodeDecodeError:
                _l.warning("File %s is not ASCII encoded. Skipping.", full_path)
                continue

            # Walk functions from bottom to top so earlier line numbers never shift.
            for fn in sorted(functions, key=lambda f: f.start_line, reverse=True):
                if self.is_c:
                    tracer_len = len(self.TRACER_PRINT_TEMPLATE % fn.name)
                    tracer_line = self.trace_code_insert % (fn.name, tracer_len - 2)
                    if self.write_illegal:
                        tracer_line = self.C_BACKUP_INSERT % fn.name
                        # you cant ever insert imports into projects like sqlite that do an amalgamation of all files
                        if not self._is_sqlite:
                            self.trace_import_insert = "#include <stdio.h>\n"
                else:
                    tracer_line = self.trace_code_insert % fn.name

                if fn.is_macro:
                    # we cant handle macros right now
                    continue

                start_idx = fn.start_line - 1  # no offset tracking needed
                end_idx = fn.end_line - 1
                total_lines = fn.end_line - fn.start_line
                if total_lines < 3 and not fn.is_macro:
                    # _l.warning(
                    #     "Function %s in %s is too short (%d lines) to instrument. Skipping.",
                    #     fn.name,
                    #     rel_file_path,
                    #     total_lines,
                    # )
                    continue

                inserted = False
                body_delimeter = "{"
                line_ender = "\n\n"
                if fn.is_macro:
                    body_delimeter = "\\\n"
                    line_ender = " \\\n"

                for j in range(start_idx, len(file_lines)):
                    if j >= end_idx:
                        # If we reach the end of the function, we can stop looking.
                        break

                    brace_pos = file_lines[j].find(body_delimeter)
                    if brace_pos == -1:
                        continue

                    # Inline tracer if there’s code after the opening brace …
                    if brace_pos < len(file_lines[j].rstrip()) - 1:
                        file_lines[j] = (
                                file_lines[j][: brace_pos + 1]
                                + tracer_line
                                + file_lines[j][brace_pos + 1:]
                        )
                    # … otherwise add a new line right below it.
                    else:
                        file_lines.insert(j + 1, tracer_line + line_ender)
                    inserted = True
                    inst_count += 1
                    break

                if not inserted:
                    _l.warning(
                        "Warning: No opening brace found for function %s in %s %s",
                        fn.name,
                        rel_file_path,
                        ("" if not fn.is_macro else "(macro)"),
                    )

            # Overwrite the file with the updated contents.
            with open(full_path, "w", encoding="utf-8") as source_file:
                # add the import if needed
                if self.trace_import_insert:
                    file_lines.insert(0, self.trace_import_insert + "\n")

                source_file.writelines(file_lines)

        _l.info("Instrumented %d functions in %d files", inst_count, len(self.sorted_functions))

    def instrument(self, **kwargs):
        self.instrument_functions()

        # compile and reset the source
        _l.info("Compiling instrumented code")
        flags = None
        if self.is_c:
            flags = "-Wno-error=unused-result"
        success, reason = self.program.compile(edited_in_place=True, print_output=True, flags=flags, get_cached_build=True)
        if not success:
            if self.write_illegal:
                # give sqlite another chance to compile
                success, reason = self.program.compile(edited_in_place=True, print_output=True, flags=flags)
                if not success:
                    raise RuntimeError("Failed to instrument")
            # attempt once more, but ban more risky insertion methods
            self.write_illegal = True
            self.instrument_functions()
            success, reason = self.program.compile(edited_in_place=True, print_output=True, flags=flags)
            if not success:
                raise RuntimeError(f"Failed to instrument: {reason}")

        self.is_instrumented = True
        _l.info("Instrumented code compiled successfully")

    def _trace(self, program_input: ProgramInput, name_only=False, **kwargs) -> list[PoI] | list[str]:
        _l.info("Running instrumented code with Crashing Input")
        stdout, stderr = self.program.execute(program_input)

        if stderr and self.TRACER_HIT_SYM.encode() in stderr:
            search_data = stderr
        elif stdout and self.TRACER_HIT_SYM.encode() in stdout:
            search_data = stdout
        else:
            raise RuntimeError(f"No tracing occurred while running the tracer!")

        call_trace = []
        pattern = re.compile(DumbCallTracer.TRACER_REGEX, re.MULTILINE)
        matches = pattern.finditer(search_data)
        for match in matches:
            call_trace.append(match.group(1).decode())
        if name_only:
            return call_trace
        functions = []
        for function_name in call_trace:
            func = self.program.code.functions_by_name(function_name)
            if func is None:
                # _l.warning(f"Function %s not found in the code but was generated by CallTraceAnalysis. Look into it?!?", function_name)
                continue

            functions.extend(func)
        return [PoI(code_func, sources=[PoISource.CALL_TRACE]) for code_func in functions]
