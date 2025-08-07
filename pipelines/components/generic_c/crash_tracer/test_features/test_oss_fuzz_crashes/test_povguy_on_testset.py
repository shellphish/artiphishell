import csv
import hashlib
import os
import pandas as pd

import tqdm
import yaml

import sys

sys.path.append('../../../../common/base/crs-utils/src/shellphish_crs_utils/result_parsers/')
from asan import parse, extract_asan_report

sanitizers = [
    'AddressSanitizer: heap-buffer-overflow ',
    'AddressSanitizer: heap-use-after-free',
    'AddressSanitizer: stack-buffer-underflow',
    'AddressSanitizer: stack-buffer-overflow',
    'AddressSanitizer: memcpy-param-overlap',
    'AddressSanitizer: container-overflow',
    'AddressSanitizer: SEGV',
    'AddressSanitizer: use-after-poison',
    'AddressSanitizer: attempting free on address which was not malloc()-ed',
    'AddressSanitizer: attempting double-free',
    'AddressSanitizer: global-buffer-overflow',
    'AddressSanitizer: negative-size-param',
    'AddressSanitizer: dynamic-stack-buffer-overflow',
    'AddressSanitizer: stack-use-after-return',
    'AddressSanitizer: stack-use-after-scope',
    'AddressSanitizer: unknown-crash',
    'AddressSanitizer: bad parameters to __sanitizer_',
    'MemorySanitizer: use-of-uninitialized-value',
    'MemorySanitizer: CHECK failed',
    'UndefinedBehaviorSanitizer: undefined-behavior',
    'UndefinedBehaviorSanitizer: SEGV',
    'MemorySanitizer: SEGV',
    'libFuzzer: fuzz target exited',
    'libFuzzer: fuzz target overwrites its const input',
    'libFuzzer: deadly signal',
    'libFuzzer: out-of-memory',
]
sanitizers = {f'id_{i}': sanitizer for i, sanitizer in enumerate(sanitizers)}
progress = tqdm.tqdm(os.listdir('test_reports/'))
for f in progress:
    with open(f'test_reports/{f}', 'rb') as in_file:  
        stderr = in_file.read()

    try:
        # print(f'Processing {f}')
        progress.set_description(f'Processing {f}')

        extracted = extract_asan_report(stderr, sanitizers)
        assert extracted
        parsed = parse(stderr, sanitizers)

        assert parsed['triggered_sanitizers']
        assert len(parsed['reports']) > 0
        for report in parsed['reports']:
            assert 'error_line' in report
            assert 'triggered_sanitizers' in report and report['triggered_sanitizers']
            assert 'report' in report
            assert type(report['report']) is str and report['report']
            for sanitizer in report['triggered_sanitizers']:
                assert sanitizers[sanitizer] in report['report']
                # assert sanitizers[sanitizer] in report['error_line']
                allowed_prefixes = ['', '==<MARKER>==', '==<MARKER>== ']
                assert any(report['report'].startswith(prefix +report['error_line']) for prefix in allowed_prefixes)
            # asssert

    except Exception as e:
        print(stderr.decode('utf-8', errors='ignore'))
        print(f'Error processing {f}: {e}')
        raise

   
