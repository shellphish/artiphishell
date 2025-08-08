import os
import abc
import math
import shutil
import hashlib
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, Generic, Iterator, List, Optional, Tuple, TypeVar

class GrammarNotValid(Exception):
    def __init__(self, failure_reason: str):
        self.failure_reason = failure_reason
        super().__init__(failure_reason)

class GrammarInput(abc.ABC):
    @abc.abstractmethod
    def to_bytes(self) -> bytes:
        raise NotImplementedError
    
    @abc.abstractmethod
    def to_mutatable_repr(self):
        raise NotImplementedError
    
GrammarInputType = TypeVar('GrammarInputType', bound=GrammarInput)

class Grammar(abc.ABC, Generic[GrammarInputType]):
    @classmethod
    @abc.abstractmethod
    def check_grammar(cls, grammar: str) -> Optional[GrammarNotValid]:
        raise NotImplementedError

    @abc.abstractmethod
    def produce_input(self, count: int, output_dir: Path, unique: bool=False) -> Iterator[bytes]:
        raise NotImplementedError

    @classmethod
    @abc.abstractmethod
    def from_string(clz, grammar: str):
        raise NotImplementedError
    
    @abc.abstractmethod
    def to_string(self) -> str:
        raise NotImplementedError

    @abc.abstractmethod
    def get_example_grammars(self) -> List[str]:
        raise NotImplementedError

        
NAUTILUS_ROOT = Path(__file__).parent.parent.parent.parent / 'libs' / 'nautilus'
assert NAUTILUS_ROOT.is_dir(), f'{NAUTILUS_ROOT} is not a directory'
NAUTILUS_FUZZER_BIN_PATH = NAUTILUS_ROOT / 'target' / 'release'
assert NAUTILUS_FUZZER_BIN_PATH.is_dir(), f'{NAUTILUS_FUZZER_BIN_PATH} is not a directory'
NAUTILUS_GENERATOR_PATH = NAUTILUS_FUZZER_BIN_PATH / 'generator'
assert NAUTILUS_GENERATOR_PATH.is_file(), f'{NAUTILUS_GENERATOR_PATH} is not a file'

EXAMPLE_PY_GRAMMAR_PATH = NAUTILUS_ROOT / 'grammars' / '_orig_grammar_py_example.py'

class NautilusPythonGrammar(Grammar):
    __GRAMMAR_TYPE__ = 'nautilus-python'
    def __init__(self, grammar: str):
        self.grammar: str = grammar
        self.grammar_tmp_path: Path = Path(tempfile.NamedTemporaryFile(suffix='.py', delete=False).name)
        self.output_tmp_dir: Path = Path(tempfile.mkdtemp())
        with self.grammar_tmp_path.open('w') as f:
            f.write(self.grammar)

    @classmethod
    def from_string(cls, grammar: str):
        return cls(grammar)
    def to_string(self) -> str:
        return self.grammar
    
    def produce_input(self, count, unique = False):
        with tempfile.TemporaryDirectory() as output_dir:
            # print(f'Generating {count} inputs to {output_dir}')
            for i, path in enumerate(self.produce_input_files(count, Path(output_dir), unique=unique)):
                res = path.read_bytes()
                # print(f'Generated {i+1}/{count} inputs: {path} {res!r}')
                yield res

    @classmethod
    def check_grammar(cls, grammar: str) -> Optional[GrammarNotValid]:
        exit_code, stdout, stderr = NautilusPythonGrammar(grammar).generator(1)
        if exit_code != 0:
            # discard lines with RUST_BACKTRACE=1 from stderr
            stderr = b'\n'.join(l for l in stderr.split(b'\n') if b'RUST_BACKTRACE=1' not in l)
            return GrammarNotValid(stderr.decode())
        return None

    def generator(self, num_inputs, corpus_dir=None, depth=200, verbose: bool=False):
        process = subprocess.Popen(
            [
                NAUTILUS_GENERATOR_PATH,
                '-n', str(num_inputs),
                '-g', str(self.grammar_tmp_path),
                '-t', str(depth),
                '-r', "/tmp/ronald",
                '-s',
            ] + (['-v'] if verbose else [])
              + (['-c', str(corpus_dir)] if corpus_dir else []),
            cwd=str(self.output_tmp_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        try:
            stdout, stderr = process.communicate(timeout=60)
            exit_code = process.returncode
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            exit_code = process.returncode
        return exit_code, stdout, stderr

    def produce_input_files(self, count: int, output_dir: Path, max_tries: int=3, unique: bool=False) -> Iterator[Path]:
        output_dir = Path(output_dir) # ensure it's a Path
        for i in range(max_tries):
            cur_outputs = os.listdir(output_dir)
            if len(cur_outputs) >= count:
                break
            needed = count - len(cur_outputs)
            to_generate = int(max(math.ceil(needed * 1.2), needed + 20)) # generate 20% more than we need to account for collisions
            corpus_dir = self.output_tmp_dir / 'corpus'
            exit_code, stdout, stderr = self.generator(to_generate, corpus_dir, verbose=False)
            assert exit_code == 0, f'# Error generating inputs: stdout={stdout.decode()} stderr={stderr.decode()}'

            for f in os.listdir(corpus_dir):
                out_name = f
                if unique:
                    with open(corpus_dir / f, 'rb') as _f:
                        hash = hashlib.sha256(_f.read()).hexdigest()
                    out_name = hash
                    if hash in cur_outputs:
                        os.unlink(corpus_dir / f)
                        continue
                if len(cur_outputs) < count:
                    os.rename(corpus_dir / f, output_dir / out_name)
                    cur_outputs.append(out_name)
                    yield output_dir / out_name
                else:
                    os.unlink(corpus_dir / f)

        shutil.rmtree(self.output_tmp_dir / 'corpus')
        # assert len(os.listdir(output_dir)) == count, f'Expected {count} inputs, got {len(os.listdir(output_dir))}: {os.listdir(output_dir)}'
        assert len(os.listdir(self.output_tmp_dir)) == 0
        return

    @staticmethod
    def get_example_grammars():
        return [EXAMPLE_PY_GRAMMAR_PATH.read_text()]
        
