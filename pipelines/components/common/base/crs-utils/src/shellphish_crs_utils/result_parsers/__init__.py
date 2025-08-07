import traceback
from typing import Dict
from .jazzer import parse as parse_jazzer
from .asan import parse as parse_asan
from .kasan import parse as parse_kasan

def parse_pov_result(run_pov_result, sanitizers: Dict[str, str]):
    # changing stderr to stderr + stdout, since some targets may put the error to stdout, like the tipc target
    stderr_bytes: bytes = run_pov_result['stderr']
    stdout_bytes: bytes = run_pov_result['stdout']
    stdall_bytes = stdout_bytes + b'\n' + stderr_bytes
    triggered_sanitizers = [id for id, sanitizer_string in sanitizers.items() if sanitizer_string.encode() in stdall_bytes]
    triggered_sanitizers = list(sorted(triggered_sanitizers))
    try:
        if b"Java Exception" in stdall_bytes:
            return {
                "parser": "jazzer",
                "jazzer": parse_jazzer(stdall_bytes, sanitizers),
                # "unparsed": run_pov_result['stderr'],
                'triggered_sanitizers': triggered_sanitizers,
            }
        elif b'KernelAddressSanitizer' in stdall_bytes:
            return {
                "parser": "kasan",
                "kasan": parse_kasan(stdall_bytes, sanitizers),
                # "unparsed": run_pov_result['stderr'],
                'triggered_sanitizers': triggered_sanitizers,
            }
        elif any(v in stdall_bytes for v in [b"AddressSanitizer", b'MemorySanitizer', b'UndefinedBehaviorSanitizer', b'LeakSanitizer']):
            return {
                "parser": "asan",
                "asan": parse_asan(stdall_bytes, sanitizers),
                # "unparsed": run_pov_result['stderr'],
                'triggered_sanitizers': triggered_sanitizers,
            }
        return {
            "parser": "none",
            "unparsed": stdall_bytes,
            'triggered_sanitizers': triggered_sanitizers,
        }
    except Exception as e:
        # raise NotImplementedError(f"Unknown sanitizer in stderr: {run_pov_result['stderr']!r}")
        return {
            "parser": "failed",
            "exception": str(e),
            "traceback": traceback.format_exc(),
            "unparsed": stdall_bytes,
            'triggered_sanitizers': triggered_sanitizers,
            }