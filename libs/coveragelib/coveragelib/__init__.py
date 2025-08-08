import logging
from pathlib import Path
from typing import Any, Union
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from shellphish_crs_utils import LOG_FORMAT
import yaml

logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
log = logging.getLogger("coveragelib")

class Parser:
    def parse(self, coverage_path: Union[Path, str], target_dir):
        raise NotImplementedError

    def parse_values(self, oss_fuzz_project: OSSFuzzProject, coverage_path: Union[Path, str]) -> Any:
        raise NotImplementedError

    def get_internal_cmd(self, extra_vars=None):
        # This returns the command that is executed inside the target container
        # at the end of the tracing process.
        # We prefer this instead of using oss-fuzz-run-custom because so we don't have 
        # to spawn multiple containers.
        return None

from .trace import Tracer
from .yajta import Yajta
from .pintrace import Pintracer, PintracerWithSanitizer