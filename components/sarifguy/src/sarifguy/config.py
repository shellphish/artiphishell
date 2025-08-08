import os
from dataclasses import dataclass, field

@dataclass
class CONFIG:
    # services
    use_codeql_server: bool = True

    is_local_run: bool = os.getenv('LOCAL_RUN') == 'True'
    is_permanence_on: bool = False


    nap_duration: int = 7 # this is in minutes
    nap_mode: bool = True
    nap_snoring: int = 60 # this is in seconds
    nap_becomes_death_after: int = 20

    # llms
    sarif_tg_guy_llms: list = field(default_factory=lambda: ['claude-3.5-sonnet', 'gpt-4.1'])

    # others

Config = CONFIG()