
import os

from enum import Enum
from dataclasses import dataclass, field


# Define an enum for the patcherq modes [patch, sarif, refine]
class CRSMode(Enum):
    FULL = 'full'
    DELTA = 'delta'
    def __str__(self):
        return self.value


@dataclass
class CONFIG:

    crs_mode: CRSMode = CRSMode.FULL

    # services
    use_codeql_server: bool = True
    is_permanence_on: bool = False

    # running state
    # (these are set dynamically by discoguy)
    is_local_run: bool = os.getenv('LOCAL_RUN') == 'True'

    # MAX budget given to discovery guy
    # TODO(FINALDEPLOY)
    scanguy_budget_limit = 10

Config = CONFIG()
