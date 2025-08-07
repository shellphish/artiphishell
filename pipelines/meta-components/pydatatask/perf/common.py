from typing import Callable
from pathlib import Path
import shutil
import subprocess
import urllib.request

base = Path(__file__).parent / "data"
base.mkdir(exist_ok=True)


def acquire(url: str) -> Path:
    basename = url.replace("/", "\\")
    result = base / basename
    if result.exists():
        return result
    with urllib.request.urlopen(url) as fp, open(result, "wb") as fp2:
        shutil.copyfileobj(fp, fp2)
    return result


def transform(in_path: Path, transformation: str):
    def wrapper(f: Callable[[Path, Path], None]) -> Path:
        out_path = base / f"{in_path.name}_{transformation}"
        if not out_path.exists():
            try:
                f(in_path, out_path)
            except:
                shutil.rmtree(out_path)
                raise
        return out_path

    return wrapper


def unpack(in_path: Path, out_path: Path):
    out_path.mkdir()
    subprocess.run(["tar", "-xf", in_path], cwd=out_path, check=True)


def transform_unpack(in_path: Path) -> Path:
    return transform(in_path, "unpack")(unpack)
