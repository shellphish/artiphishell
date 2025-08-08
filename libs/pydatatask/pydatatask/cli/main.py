"""This module is called when you run `python -m pydatatask`.

Its whole purpose is to parse pipeline.yaml files and then feed the result into pydatatask.main.main().
"""

from typing import Optional
import logging
import sys

from pydatatask.main import main as real_main
from pydatatask.staging import get_current_directory_pipeline

logging.basicConfig(format="%(asctime)s: %(name)s:%(levelname)s - %(message)s")


def _main() -> Optional[int]:
    try:
        pipeline = get_current_directory_pipeline()
    except ValueError as e:
        print(e.args[0], file=sys.stderr)
        return 1
    real_main(pipeline)
    return 0


if __name__ == "__main__":
    sys.exit(_main())
