from pathlib import Path

# from . import challenge_project
from . import oss_fuzz as oss_fuzz

# from . import compilation_cache
from . import filesystem as filesystem
from . import pydatatask as pydatatask
from . import models as models

ARTIPHISHELL_DIR = Path(__file__).parent.parent.parent.parent.parent
LIBS_DIR = ARTIPHISHELL_DIR / "libs"
C_INSTRUMENTATION_DIR = LIBS_DIR / "c-instrumentation"
ORGANIZER_LIBS_DIR = LIBS_DIR / "organizers"
ORGANIZER_DEDUP_DIR = ORGANIZER_LIBS_DIR / "dedup"
ORGANIZER_EXAMPLE_CHALLENGE_EVAL_DIR = ORGANIZER_LIBS_DIR / "example-challenge-evaluation"
BLOBS_DIR = ARTIPHISHELL_DIR / "blobs"

LOG_FORMAT = (
    "%(asctime)s [%(levelname)-8s] "
    "%(name)s:%(lineno)d | %(message)s"
)

assert ARTIPHISHELL_DIR.is_dir()
assert LIBS_DIR.is_dir()
