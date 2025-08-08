
import os

from enum import Enum
from dataclasses import dataclass, field


# Define an enum for the patcherq modes [patch, sarif, refine]
class CRSMode(Enum):
    FULL = 'full'
    DELTA = 'delta'
    def __str__(self):
        return self.value

# Define an enum for the discoguy modes [pois, sarif, bypass]
class DiscoverGuyMode(Enum):
    POIS = 'pois'
    SARIF = 'sarif'
    BYPASS = 'bypass'
    POISBACKDOOR = 'poisbackdoor'
    DIFFONLY = 'diffonly'

    def __str__(self):
        return self.value


@dataclass
class CONFIG:

    crs_mode: CRSMode = CRSMode.FULL
    discoveryguy_mode: DiscoverGuyMode = DiscoverGuyMode.POIS

    # services
    use_codeql_server: bool = True
    is_permanence_on: bool = False

    # running state
    # (these are set dynamically by discoguy)
    is_local_run: bool = os.getenv('LOCAL_RUN') == 'True'
    disco_guy_mode: str = ''
    disco_guy_from: str = ''

    # for nap mode
    nap_mode: bool = True
    # What is the next N minute mark we are waking up from the nap
    nap_duration: int = 8 # this is in minutes
    # If we are in nap mode, we will wait N seconds before trying to wake up
    nap_snoring: int = 60
    # If we wake up N times in a row and there is no budget, we kill the component.
    nap_becomes_death_after: int = 100
    max_analysis_report_length: int = 10000
    min_analysis_report_length: int = 3000
    # knobs

    # Whether we skip already pwned vulnerabilities
    skip_already_pwned: bool = True

    # MAX budget given to discovery guy
    # TODO(FINALDEPLOY)
    discoguy_budget_limit = 100
    # TODO(FINALDEPLOY)
    discoguy_from_diff_budget_limit = 20

    # How many iterations before we stop trying to find a bypass for a patch
    max_attempts_bypass = 5

    # How many times we try to exploit a warning per single harness in scope
    exploit_dev_max_attempts_per_sink: int = 2

    # How many times we will try to fix the python script in a row
    exploit_dev_max_attempts_regenerate_script: int = 3

    # When a code-swipe report is available, we will extract the top N functions
    max_pois_to_check: int = 300

    # When multiple harnesses are available we will use the top N
    max_harness_per_poi: int = 5

    # How many bytes we want to extract from a template benign seed (when available)
    max_bytes_for_benign_seed_template: int = 200

    # Weather we check the top 5 warnings with opus or not
    check_top_n_with_opus: bool = False
    top_n_with_opus = 3
    max_money_spent_with_opus: int = 5

    # If we are switching to opus too many times in a row, we just stop it (expensive!)
    max_opus_for_jimmypwn: int = 4

    # llms
    jimmypwn_llms: list = field(default_factory=lambda: ['claude-4-sonnet', 'claude-4-opus'])

    jimmypwn_llms_opus_first: list = field(default_factory=lambda: ['claude-4-opus','claude-4-sonnet'])
    jimmypwn_llms_opus_second: list = field(default_factory=lambda: ['claude-4-sonnet', 'claude-4-opus'])
    jimmypwn_llms_no_opus: list = field(default_factory=lambda: ['claude-4-sonnet'])

    summary_agent_llms: list = field(default_factory=lambda: ['o3', 'claude-4-sonnet'])

    honey_select_llms: list = field(default_factory=lambda: ['claude-4-sonnet', 'o3'])

    bypass_agents_llms: list = field(default_factory=lambda: ['claude-4-sonnet', 'o3'])

    # others
    suppress_run_pov_output: bool = True

    max_diff_lines_for_summary: int = 700

    send_fuzz_request: bool = False # 🥹bye

Config = CONFIG()
