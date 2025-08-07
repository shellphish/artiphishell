
"""
{
  "sanitizer": "OS Command Injection",
  "backtrace": "== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical: OS Command InjectionExecuting OS commands with attacker-controlled data can lead to remote code execution.Found in argument 0\tat com.code_intelligence.jazzer.sanitizers.OsCommandInjection.ProcessImplStartHook(OsCommandInjection.java:31)\tat java.base/java.lang.ProcessBuilder.start(ProcessBuilder.java:1109)\tat java.base/java.lang.ProcessBuilder.start(ProcessBuilder.java:1073)\tat io.jenkins.plugins.UtilPlug.UtilMain.createUtils(UtilMain.java:194)\tat io.jenkins.plugins.UtilPlug.UtilMain.doexecCommandUtils(UtilMain.java:157)\tat PipelineCommandUtilFuzzer.fuzzerTestOneInput(PipelineCommandUtilFuzzer.java:66)"
}
"""

import json
import re  
import argparse
import hashlib
import shutil
from pathlib import Path
from typing import Dict


def extract_jazzer_report(stderr: bytes, sanitizers: Dict[str, str]):
    if not stderr:
        return None
    
    raw_report = stderr
    print(f"Searching for reports in {len(stderr)} bytes")
    all_lines = stderr.split(b'\n')
    report_search = ((idx, x) for idx, x in enumerate(all_lines) if x.strip().startswith(b"== Java Exception:"))
    raw_reports = []
    while current_report := next(report_search, None):
        line_no, line = current_report
        report_end = next((idx for idx, x in enumerate(all_lines[line_no:]) if x.strip() == b"== libFuzzer crashing input =="), None)
        if report_end is None:
            raw_reports.append(all_lines[line_no:])
            break
        print(line_no, report_end)
        raw_reports.append(all_lines[line_no:line_no+report_end+1])

    reports = []
    for raw_report in raw_reports:
        report = {}
        bytes_report = b'\n'.join(raw_report)
        report["report"] = bytes_report.decode("utf-8", "ignore")
        report["triggered_sanitizers"] = [k for k, v in sanitizers.items() if v.encode() in bytes_report]
        report["error_line"] = raw_report[0].decode("utf-8", "ignore")
        stack_trace = []
        argument = None
        for line in raw_report:
            line = line.strip().decode("utf-8", "ignore")
            if line.startswith("Found in argument"):
                argument = line[len("Found in argument "):]
            if not line.startswith("at"):
                continue
            trace_line = {"text": line, "package": None, "file": None, "line": None, "function": None}
            try:
                package, rest = line.split('(')
                package = package[3:]
                trace_line["package"] = package
                trace_line["function"] = package.split('.')[-1]
                trace_line["class"] = ".".join(package.split('.')[:-1])
                file, line_no = rest.split(":")
                trace_line["file"] = file
                trace_line["line"] = line_no[:-1]
            except:
                pass
            stack_trace.append(trace_line)
        report["argument"] = argument
        report["stack_trace"] = stack_trace
        reports.append(report)
    return reports

def parse(crash_report: bytes, sanitizers: Dict[str, str]):

    
    triggered_sanitizers = []
    for key, value in sanitizers.items():
        if value.encode() in crash_report:
            triggered_sanitizers.append(key)
        
    reports = extract_jazzer_report(crash_report, sanitizers)

    # Creating the JSON object
    crash_data = {
        "triggered_sanitizers": triggered_sanitizers,
        "reports": reports
    }
    return crash_data