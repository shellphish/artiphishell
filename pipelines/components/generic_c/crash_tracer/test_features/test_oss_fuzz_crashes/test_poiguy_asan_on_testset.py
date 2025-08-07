import csv
import glob
import hashlib
import os
import shutil
import pandas as pd

import tqdm
import yaml

import sys

sys.path.append('../../../../common/base/crs-utils/src/')
from shellphish_crs_utils.result_parsers.asan import parse as povguy_parse, extract_asan_report as povguy_extract
sys.path.append('../../../../generic_c/crash_tracer/')
from asan2report import create_asan_report
sys.path.append('../../../../common/poiguy/')
from ASAN.asan import asan_report_parser, dump_asn_poi

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


MANUALLY_CHECKED_POI_INPUTS = {
    'freetype2_5f39b81001b11f884b0dd3f06291f06ec04ce6f5187c38e42f32b3db45959d71.txt': (0, 0),
    'unicorn_79cca4c5ec0ed91eedf274cb7e2393cdedc94d51d56787ff80b3ae910c6d67ee.txt': (3, 3),
    'opus_79c34f300f2359144dc794df4d1b6702deee09898ad91e613fd3dbdf81894e9f.txt': (1, 1),
    'proj.4_64ae2cec08aaff4e454283d2607e1a12775e554e200133c3be064d7fb9ae1338.txt': (1, 1),
    'unicorn_ed29a9934c736d3c70781ab6763690e2361514db815017d27e4084ec79f951a9.txt': (1, 1),
    'uWebSockets_66f7b6987f22de265809d2222a5fb620d70b1c716bb142e8a1cbc188d61a8c5e.txt': (1, 1),
    'freetype2_ca58550168e1bd7a0d3c17fe08558c5e53d2e907b38846b7ac09f3a00e2f0e82.txt': (0, 0),
    'unicorn_24d56d626e002040ff7d54748f9f2b5f713147413cdd362e93384054d392f18f.txt': (1, 1),
    'fluent-bit_542777f1824587edf653e786b445924b796bb8ed911c1651b700cca7467fc39f.txt': (1, 1),
}

progress = tqdm.tqdm(os.listdir('test_reports/')[::-1])
for f in progress:
    with open(f'test_reports/{f}', 'rb') as in_file:  
        stderr = in_file.read()

    try:
        # print(f'Processing {f}')
        progress.set_description(f'Processing {f}')

        base_report = {
            'target_id': '1',
            'harness_info_id': '10',
            'crash_report_id': '123',
            'cp_harness_id': 'id_1',
            'cp_harness_name': 'harness_name',
            'cp_harness_binary_path': 'harness_binary_path',
            'cp_harness_source_path': 'harness_source_path',
            'fuzzer': 'fuzzer',
        }
        
        run_pov_result = dict(base_report)
        run_pov_result['consistent_sanitizers'] = ['id_1']
        run_pov_result['inconsistent_sanitizers'] = ['id_2']
        run_pov_result['sanitizer_history'] = [['id_1', 'id_2'], ['id_1']]
        run_pov_result['run_pov_result'] = {
            'stdout': b'',
            'stderr': stderr,
            'pov': povguy_parse(stderr, sanitizers=sanitizers),
        }

        asan2report = create_asan_report(run_pov_result)

        
        poiguy_asan_report = asan_report_parser(asan2report)

        if f in MANUALLY_CHECKED_POI_INPUTS:
            assert len(poiguy_asan_report['poi']) == MANUALLY_CHECKED_POI_INPUTS[f][0]
            assert len(poiguy_asan_report['call_trace']) == MANUALLY_CHECKED_POI_INPUTS[f][1]
        else:
            assert poiguy_asan_report['poi'] and len(poiguy_asan_report['poi']) > 2
            assert len(poiguy_asan_report['call_trace']) > 2

        with open('/tmp/asan_report.yaml', 'wb') as out_file:
            out_file.write(yaml.dump(asan2report).encode())

        with open('/tmp/clang_index.csv', 'w') as f:
            f.write('''func_name,function_signature,filename,filepath,start_line,end_line,start_column,end_column,start_offset,end_offset,line_map
__wrap_getsockopt,"harnesses/pov_harness.cc:528:1::int __wrap_getsockopt(int, int, int, void *, socklen_t *)",pov_harness.cc,harnesses/pov_harness.cc,528,539,1,2,12979,13250,"[(528, 'int __wrap_getsockopt(int sockfd, int level, int optname,'), (529, '                      void *optval, socklen_t *optlen)'), (530, '{'), (531, '  int *n = (int*)optval;'), (532, ''), (533, '  // The getsockopt wants to confirm that the socket is a sock_stream'), (534, '  // SOL_SOCKET, SO_TYPE'), (535, ''), (536, '  *n = SOCK_STREAM;'), (537, ''), (538, '  return 0;'), (539, '}'), (540, '')]"
__wrap_epoll_wait,"harnesses/pov_harness.cc:469:1::int __wrap_epoll_wait(int, struct epoll_event *, int, int)",pov_harness.cc,harnesses/pov_harness.cc,469,473,1,2,11627,11802,"[(469, 'int __wrap_epoll_wait(int epfd, struct epoll_event *events,'), (470, '                      int maxevents, int timeout)'), (471, '{'), (472, '  return __real_epoll_wait(epfd, events, maxevents, timeout);'), (473, '}'), (474, '')]"
__wrap_listen,"harnesses/pov_harness.cc:512:1::ssize_t __wrap_listen(int, void *, size_t)",pov_harness.cc,harnesses/pov_harness.cc,512,518,1,2,12687,12824,"[(512, 'ssize_t __wrap_listen(int fd, void *buf, size_t bytes)'), (513, '{'), (514, '  // There should only be one listener set'), (515, '  http_listen_fd = fd;'), (516, ''), (517, '  return 0;'), (518, '}'), (519, '')]"
__wrap_epoll_ctl,"harnesses/pov_harness.cc:463:1::int __wrap_epoll_ctl(int, int, int, struct epoll_event *)",pov_harness.cc,harnesses/pov_harness.cc,463,466,1,2,11489,11614,"[(463, 'int __wrap_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)'), (464, '{'), (465, '  return __real_epoll_ctl(epfd, op, fd, event);'), (466, '}'), (467, '')]"
__wrap_getpwnam,harnesses/pov_harness.cc:557:1::struct passwd * __wrap_getpwnam(const char *),pov_harness.cc,harnesses/pov_harness.cc,557,561,1,2,13474,13559,"[(557, 'struct passwd *__wrap_getpwnam(const char *name)'), (558, '{'), (559, '  pwd.pw_uid = 1;'), (560, '  return &pwd;'), (561, '}'), (562, '')]"
__wrap_epoll_create1,harnesses/pov_harness.cc:457:1::int __wrap_epoll_create1(int),pov_harness.cc,harnesses/pov_harness.cc,457,460,1,2,11398,11476,"[(457, 'int  __wrap_epoll_create1(int flags)'), (458, '{'), (459, '  return __real_epoll_create1(flags);'), (460, '}'), (461, '')]"
__wrap_accept,"harnesses/pov_harness.cc:476:1::int __wrap_accept(int, struct sockaddr *, socklen_t *)",pov_harness.cc,harnesses/pov_harness.cc,476,497,1,2,11815,12445,"[(476, 'int __wrap_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)'), (477, '{'), (478, '  struct sockaddr_in * sin = (struct sockaddr_in *)addr;'), (479, ''), (480, ""  // We shouldn't ever actually call accept""), (481, '  if ( sockfd == http_listen_fd && http_client_fd == -1) {'), (482, '    // We do want a real socket though'), (483, '    http_client_fd = socket( AF_INET, SOCK_STREAM, 0);'), (484, ''), (485, '    // Setup the appropriate false connection information'), (486, '    sin->sin_family = AF_INET;'), (487, '    sin->sin_port = htons(9999);'), (488, '    sin->sin_addr.s_addr = 0x0100007f; // ""127.0.0.1""'), (489, ''), (490, '    return http_client_fd;'), (491, '  }'), (492, ''), (493, '  // Otherwise, set errno and return a failure'), (494, '  errno = 11; // NGX_EAGAIN'), (495, ''), (496, '  return -1;'), (497, '}'), (498, '')]"
''')

        poi_reports_dir = '/tmp/poi_reports/'
        shutil.rmtree(poi_reports_dir, ignore_errors=True)
        os.makedirs(poi_reports_dir, exist_ok=True)
        
        dump_asn_poi(
            target_id=1,
            asan_crash_report='/tmp/asan_report.yaml',
            clang_index_csv='/tmp/clang_index.csv',
            poi_reports_dir='/tmp/poi_reports/'
        )
        poi_reports = glob.glob(poi_reports_dir + f'poi-report-1-*.yaml')
        assert len(poi_reports) == 1
        with open(poi_reports[0], 'rb') as f:
            poiguy_poi_report = yaml.safe_load(f)
            if f not in MANUALLY_CHECKED_POI_INPUTS:
                assert len(poiguy_poi_report['pois']) == len(poiguy_asan_report['poi'])
            else:
                assert len(poiguy_poi_report['pois']) == MANUALLY_CHECKED_POI_INPUTS[f][0]
            assert len(poiguy_poi_report['stack_traces'])

            assert poiguy_poi_report['scanner'] == 'asan'
            assert poiguy_poi_report['detection_strategy'] == 'fuzzing'
            assert poiguy_poi_report['additional_information']['asan_report_data'] == asan2report
            for key, value in base_report.items():
                key_map = {'crash_report_id': 'crash_id', 'cp_harness_id': 'harness_id'}
                assert poiguy_poi_report[key_map.get(key, key)] == value

    except Exception as e:
        print(stderr.decode('utf-8', errors='ignore'))
        print(f'Error processing {f}: {e}')
        raise

   
