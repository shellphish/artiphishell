

import enum
from pathlib import Path
from typing import Dict
from shellphish_crs_utils.models.crash_reports import LosanSanitizerEnum

CUR_DIR = Path(__file__).parent
def read_sanitizer_description(sanitizer: LosanSanitizerEnum) -> str:
    with open(CUR_DIR / f"{sanitizer.value}.txt") as f:
        return f.read()
    
def sanitizer_descriptions() -> Dict[LosanSanitizerEnum, str]:
    return {
        sanitizer: read_sanitizer_description(sanitizer)
        for sanitizer in LosanSanitizerEnum
    }