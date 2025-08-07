from typing import List, Tuple, Dict, Any

from .invarience_report import InvarianceReport, InvarianceViolation


def parse_invariance_report(raw_data: dict) -> List[InvarianceReport]:
    if not raw_data:
        raise ValueError("Empty invariance report data")

    reports = []
    for target_name, target_data in raw_data.items():
        if not isinstance(target_data, dict):
            raise ValueError("Invalid invariance report data")

        reports.append(InvarianceReport.from_raw_data(target_data, unique_name=target_name))

    return reports
