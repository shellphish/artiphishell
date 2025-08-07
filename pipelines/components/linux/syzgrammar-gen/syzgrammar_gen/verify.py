from dataclasses import dataclass
from subprocess import PIPE
from pathlib import Path
import subprocess

@dataclass
class CompilationConfig:
    syzkaller_path: Path
    max_threads: int

@dataclass
class CompilationResult:
    success: bool
    output: str

def try_compile_grammar(
    config: CompilationConfig,
    grammar: str
) -> CompilationResult:

    with open(config.syzkaller_path / "sys/linux/harness.txt", "w") as fp:
        fp.write(grammar)

    result = subprocess.run([
            "make",
            "-C",
            config.syzkaller_path,
            "descriptions", # we only need to confirm the desciptions are good
            "-j",
            str(config.max_threads)
        ],
        stdout=PIPE,
        stderr=PIPE
    )

    stdout = result.stdout[:1000] + (result.stdout[1000:] and b'\nTruncated...\n')
    stderr = result.stderr[:1000] + (result.stderr[1000:] and b'\nTruncated...\n')

    output = f"""
### STDOUT ###
{stdout.decode()}
### STDERR ###
{stderr.decode()}
    """

    if result.returncode != 0:
        return CompilationResult(False, output)
    else:
        return CompilationResult(True, "")

