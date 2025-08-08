import os

from dataclasses import dataclass, field
from enum import Enum

# Define an enum for the patcherq modes [patch, sarif, refine]
class CRSMode(Enum):
    FULL = 'full'
    DELTA = 'delta'
    def __str__(self):
        return self.value

# Define an enum for the patcherq modes [patch, sarif, refine]
class PatcherqMode(Enum):
    PATCH = 'patch'
    SARIF = 'sarif'
    REFINE = 'refine'
    def __str__(self):
        return self.value

@dataclass
class CONFIG:

    # crs mode
    crs_mode: CRSMode = CRSMode.FULL
    
    # mode
    patcherq_mode: PatcherqMode = PatcherqMode.PATCH

    # services
    use_codeql_server: bool = True
    use_lang_server: bool = False
    use_dyva_report: bool = True

    is_local_run: bool = os.getenv('LOCAL_RUN') == 'True'
    is_permanence_on: bool = False

    nap_duration: int = 7 # this is in minutes
    nap_mode: bool = True
    nap_snoring: int = 60 # this is in seconds
    nap_becomes_death_after: int = 20
    
    # weather we should emit a bypass request or not
    emit_bypass_request: bool = False
    # weather we should emit the patched artifacts folder
    emit_patched_artifacts: bool = False

    # knobs
    max_programmer_total_attempts: int = 11
    max_programmer_attempts_compile: int = 4
    max_programmer_attempts_crash: int = 4
    max_programmer_attempts_tests: int = 2
    max_programmer_duplicate_patches: int = 3
    max_programmer_attempts_critic: int = 1
    max_sarif_attempts: int = 3
    programmer_guy_temperature_increment: float = 0.1
    triage_guy_temperature_increment: float = 0.1

    use_diff_tool_for_delta: bool = False

    # llms
    issue_llms: list = field(default_factory=lambda: ['claude-3.7-sonnet', 'gpt-4.1'])
    #triage_llms: list = field(default_factory=lambda: ['claude-3.7-sonnet', 'gpt-4.1', 'gpt-4o', 'claude-3.7-sonnet'])
    triage_llms: list = field(default_factory=lambda: ['claude-3.7-sonnet', 'claude-4-opus'])
    programmer_llms: list = field(default_factory=lambda: ['claude-3.7-sonnet'])

    # others
    greedy_patching: bool = True
    generate_sarif: bool = False
    use_critic: bool = True
    use_fuzz_pass: bool = True
    
    # TODO: THIS MUST BE TRUE
    use_build_check_pass: bool = True
    
    use_dyva_suggestions: bool = False
    suppress_build_output: bool = False
    resolve_compile_generated_files: bool = True

    fuzz_patch_time: int = 450 # seconds (7.5 minutes, very important!)
    
    programmer_brain_surgery = True

    # reg pass
    use_reg_pass: bool = True

Config = CONFIG()
