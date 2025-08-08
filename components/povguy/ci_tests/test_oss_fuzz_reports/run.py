#!/usr/bin/env python3
'''
Testing the asan parser on all old reported OSS-Fuzz crash reports
'''

import os
from pathlib import Path
import tqdm
from shellphish_crs_utils.sanitizer_parsers.asan import parse, extract_asan_report

CUR_DIR = Path(os.path.dirname(os.path.realpath(__file__)))

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
progress = tqdm.tqdm(os.listdir(CUR_DIR / 'test_reports'))
for f in progress:
    stderr = (CUR_DIR / 'test_reports' / f).read_bytes()

    try:
        progress.set_description(f'Processing {f}')

        extracted = extract_asan_report(stderr, sanitizers)
        assert extracted
        parsed = parse(stderr, sanitizers)

        assert parsed.triggered_sanitizers
        assert len(parsed.reports) > 0
        for report in parsed.reports:
            assert report.error_line
            assert report.triggered_sanitizers
            assert report.report
            for sanitizer in report.triggered_sanitizers:
                assert sanitizers[sanitizer].encode() in report.report
                # assert sanitizers[sanitizer] in report['error_line']
                allowed_prefixes = ['', '==<MARKER>==', '==<MARKER>== ']
                assert any(report.report.startswith(prefix.encode() + report.error_line.encode()) for prefix in allowed_prefixes)
            # asssert

    except Exception as e:
        print(stderr.decode('utf-8', errors='ignore'))
        print(f'Error processing {f}: {e}')
        raise e

   
