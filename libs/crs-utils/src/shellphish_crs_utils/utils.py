import contextlib
import logging
import os
from pathlib import Path
import subprocess
import time
from typing import Optional
from shellphish_crs_utils.models.target import VALID_SOURCE_FILE_SUFFIXES_C

@contextlib.contextmanager
def timed_context(_l: logging.Logger, msg: str):
    """
    Context manager to time a block of code.
    """
    start_time = time.time()
    yield
    end_time = time.time()
    _l.info(f"{msg} took {end_time - start_time:.2f} seconds")

def is_true_value(value):
    if value is None:
        return False

    elif value.lower() in ["true", "1", "yes", 'y']:
        return True

    elif value.lower() in ["false", "0", "no", 'n']:
        return False

    else:
        raise ValueError(f"Invalid value for boolean conversion: {value}")

def artiphishell_should_fail_on_error():
    return is_true_value(os.environ.get("ARTIPHISHELL_FAIL_EARLY", None))

def artiphishell_runs_in_cluster():
    return 'IN_K8S' in os.environ and os.environ['IN_K8S'] == '1'

def safe_decode_string(bs: bytes):
    assert type(bs) == bytes
    try:
        return bs.decode('utf-8')
    except UnicodeDecodeError:
        try:
            return bs.decode('latin-1')
        except UnicodeDecodeError:
            return bs.decode('utf-8', errors='replace')

def fixup_compilation_arguments(compile_args):
    for compilation_argument_infos in compile_args:
        file_name = Path(compilation_argument_infos["file"]).name
        if 'output' not in compilation_argument_infos:
            if '-c' in compilation_argument_infos['arguments']:
                # the output is just the `file` but with `.o`
                for suffix in VALID_SOURCE_FILE_SUFFIXES_C:
                    if file_name.endswith(suffix):
                        compilation_argument_infos['output'] = file_name[:-len(suffix)] + ".o"
                        break
            elif '-S' in compilation_argument_infos['arguments']:
                for suffix in VALID_SOURCE_FILE_SUFFIXES_C:
                    if file_name.endswith(suffix):
                        compilation_argument_infos['output'] = file_name[:-len(suffix)] + ".s"
                        break
            elif '-E' in compilation_argument_infos['arguments'] or '-fsyntax-only' in compilation_argument_infos['arguments']:
                continue # this cannot be helped, it just prints to stdout. If this happens, the caller just has to ignore these entries
            else:
                # Alright, game time. this runs everything and produces an executable.
                compilation_argument_infos['output'] = 'a.out'

def locate_file_for_function_via_dwarf(binary_path: Path, function_name: str) -> Optional[Path]:
    try:
      res = subprocess.check_output(
          ['llvm-dwarfdump', f'-name={function_name}', binary_path]
      )
      res = res.decode()

      file_name = None
      file_line = None
      for line in res.split('\n'):
          if 'DW_AT_decl_file'.lower() in line.lower():
              file_name = line.split('"', 1)[-1].rsplit('"', 1)[0]
          if 'DW_AT_decl_line'.lower() in line.lower():
              file_line = int(line.split('(')[-1].split(')')[0])

          if file_name and file_line:
              break

      if not file_name:
          return None

      return Path(file_name)
    except Exception as e:
        return None