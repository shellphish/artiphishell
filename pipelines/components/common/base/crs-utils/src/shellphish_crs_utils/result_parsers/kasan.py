
import os
import re
from typing import Dict

import yaml

SEPARATOR = b'=================================================================='

def triggered_sanitizers(stderr: bytes, sanitizers: Dict[str, str]):
    triggered_sanitizers = []
    for key, value in sanitizers.items():
        if value.encode() in stderr:
            triggered_sanitizers.append(key)
    return triggered_sanitizers

def clean_report(report: bytes) -> bytes:
    # this thing may need modification, but it works for now
    report = re.sub(b'of size \d+', b'of size <REDACTED>', report)
    report = re.sub(b'is located \d+ bytes', b'is located <REDACTED> bytes', report)
    report = re.sub(b'0x[0-9a-fA-F]{8,}', b'0x<REDACTED>', report)
    report = re.sub(b' is ascii string \'[^\']+\'', b'', report)
    report = re.sub(b'at addr ([0-9a-fA-F]+)',b'at addr <REDACTED>', report)
    report = re.sub(b'\[\s*\d+\.\d+\s*\]', b'', report)
    report = re.sub(b'^.*CPU.*\\n', b'', report, flags=re.MULTILINE)
    report = re.sub(b'^.*Hardware name.*\\n', b'', report, flags=re.MULTILINE)
    report = re.sub(b'\(discriminator \d+\)', b'(discriminator <REDACTED>)', report)
    report = re.sub(b'[0-9a-fA-F]{12,}', b'<REDACTED>', report)
    report = re.sub(b'Memory state around the buggy address:.*', b'', report, flags=re.DOTALL)
    report = re.sub(b'^.*refcount:.*mapcount:.*\\n', b'', report, flags=re.MULTILINE)
    report = re.sub(b'^.*entire_mapcount.*nr_pages_mapped.*\\n', b'', report, flags=re.MULTILINE)
    report = re.sub(b'^.*by task.*\\n', b'', report, flags=re.MULTILINE)
    report = re.sub(b'^.*flags: 0x.*\\n', b'', report, flags=re.MULTILINE)
    return report

def extract_kasan_report(stderr: bytes, sanitizers: Dict[str, str]):
    if not stderr:
        return None
    stderr_split = stderr.split(SEPARATOR)
    maybe_raw_reports = [stderr_split[i] for i in range(1, len(stderr_split), 2)]
    raw_reports=[]
    for maybe_raw_report in maybe_raw_reports:
        report = clean_report(maybe_raw_report)
        if report:
            result = {}
            result['triggered_sanitizers'] = triggered_sanitizers(stderr, sanitizers)
            result['report'] = report.decode('utf-8', errors='ignore') if isinstance(report, bytes) else report
            if result not in raw_reports:
                raw_reports.append(result)
    return raw_reports



def parse(stderr, sanitizers: Dict[str, str]):
    reports = extract_kasan_report(stderr, sanitizers)
    if not reports:
        return None

    triggered_sanitizers = []
    for key, value in sanitizers.items():
        if value.encode() in stderr:
            triggered_sanitizers.append(key)

    crash_data = {
        "triggered_sanitizers": triggered_sanitizers,
        "reports": reports
    }
    return crash_data

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--pov-report', type=str, help='Path to pov report')
    parser.add_argument('--sanitizers', type=str, help='Sanitizers to search for')
    args = parser.parse_args()
    sanitizers = {f'id_{i}': sanitizer for i, sanitizer in enumerate(args.sanitizers.split(','))}

    with open(args.pov_report, 'rb') as f:
        data = yaml.safe_load(f)
        stderr = data['run_pov_result']['stderr']
        print(yaml.dump(parse(stderr, sanitizers)))