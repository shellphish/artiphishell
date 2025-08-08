import os

from dataclasses import dataclass, field
from enum import Enum

@dataclass
class CONFIG:

    backdoorguy_models: list = field(default_factory=lambda: ['gpt-4.1-mini', 'claude-3.5-sonnet'])
    max_outliers = 10

    nap_duration: int = 5 # this is in minutes
    nap_mode: bool = True
    nap_snoring: int = 60 # this is in seconds
    nap_becomes_death_after: int = 10

Config = CONFIG()
