import argparse
import os
import re
import json
import logging
from io import StringIO
from pathlib import Path

import yaml

from rich.logging import RichHandler
from rich.console import Console

FORMAT = "%(message)s"
logging.basicConfig(
    level="INFO", format=FORMAT, datefmt="[%X]")

log = logging.getLogger("Asan2Report")
#log.propagate = False
log.addHandler(RichHandler(console=Console(width=180)))

from shellphish_crs_utils.models.crs_reports import ASANReport

SEPARATOR = b'=================================================================\n'

def parsed_stack_trace(stack_trace):
    if not stack_trace:
        return []
    trace = []
    for line in stack_trace.splitlines():
        line = line.strip()
        res = re.search(r'#(\d+)\s+(0x[0-9a-fA-F]+)\s+in\s+', line)
        if not res:
            continue
        depth = int(res.group(1))
        addr = int(res.group(2), 16)
        line = line[len(res.group(0)):]

        # determine whether this is a source code info
        if res := re.search(r'([^\s]*):(\d+):\d+$', line) or re.search(r'([^\s]*):(\d+)$', line):
            file = Path(res.group(1)).resolve()
            if str(file).startswith('/src'):
                file = Path("src") / file.relative_to("/src")
            line_num = int(res.group(2))
            signature = line[:-len(res.group(0))].strip()
            #print(depth, hex(addr), signature, file, line_num)
            trace.append({'depth': depth, 
                          'func_name': None, 
                          'type': 'source', 
                          'src_loc': f"{file}:{line_num}", 
                          'src_file': file, 
                          'binary': None,
                          'line': line_num, 
                          'offset': None,
                          'build_id': None,
                          'signature': signature})
        
        elif res := re.search(r'([^\s]*)(\.[ch])(pp|c)?$', line):
            file = res.group(1) + res.group(2) + (res.group(3) if res.group(3) else '')
            file = Path(file).resolve()
            if str(file).startswith('/src'):
                file = Path("src") / file.relative_to("/src") # source code is in /src when building
            signature = line[:-len(res.group(0))].strip()
            #print(depth, hex(addr), signature, file, line_num)
            trace.append({'depth': depth, 
                          'func_name': None,
                          'type': 'source', 
                          'src_loc': f"{file}:{0}", 
                          'src_file': file, 
                          'binary': None,
                          'line': 0,
                          'offset': None,
                          'build_id': None,
                          'signature': signature})

        # determine whether this is a binary info
        elif res := re.search(r'\s+\(BuildId:\s+([0-9a-fA-F]+)\)$', line):
            build_id = res.group(1)
            line = line[:-len(res.group(0))]
            res = re.search(r'([^(]+)\+0x([0-9a-fA-F]+)', line)
            assert res
            binary = Path(res.group(1)).resolve()
            try:
                src_idx = list(binary.parts).index('src')
                binary = Path(list(binary.parts)[src_idx:])
            except:
                pass
            offset = int(res.group(2), 16)
            # signature is anything before binary with trialing ) removed
            signature = line[:line.index(res.group(1))][:-1].strip()
            trace.append({'depth': depth, 
                          'func_name': None,
                          'type': 'binary', 
                          'src_loc': None,
                          'src_file': None,
                          'binary': binary, 
                          'line': None,
                          'offset': offset, 
                          'build_id': build_id, 
                          'signature': signature})

        # asan interceptors?
        # Example:
        #   printf_common(void*, char const*, __va_list_tag*) asan_interceptors.cpp.o
        elif '_start' in line:
            line: str
            signature, binary = line.split(maxsplit=1)
            binary = binary.split("+")[0].replace("(", "")
            trace.append({'depth': depth, 
                          'func_name': None,
                          'type': 'entrypoint', 
                          'src_loc': None,
                          'src_file': None,
                          'binary': binary, 
                          'line': None,
                          'offset': None,
                          'build_id': None,
                          'signature': signature})
        elif 'aflpp_driver.c' in line:
            file = Path(line.split()[-1])
            assert file.name.endswith('aflpp_driver.c')
            assert line.split()[0] == 'LLVMFuzzerRunDriver'
            binary = Path("src") / file.resolve().relative_to(os.getcwd() + "/src") # source code is in /src when building
            signature = line[:-len(str(file))].strip()
            trace.append({'depth': depth, 
                          'func_name': None,
                          'type': 'aflpp_driver', 
                          'src_loc': f"{str(binary)}:0", 
                          'src_file': binary, 
                          'binary': None,
                          'line': 0, 
                          'offset': None,
                          'build_id': None,
                          'signature': signature})
        elif res := re.search(r'\s+([^\s]*)$', line):
            # import ipdb; ipdb.set_trace()
            binary = res.group(1)
            if binary[0] == '(' and binary[-1] == ')':
                binary = binary[1:-1].split("+")[0]
            try:
                binary = Path("src") / Path(binary).relative_to(os.getcwd() + '/src')
            except ValueError:
                pass
            signature = line[:-len(res.group(0))].strip()

            if 'sanitizer_common_interceptors.inc' in line:
                trace.append({'depth': depth, 
                              'func_name': None,
                              'type': 'asan_interceptor', 
                              'src_loc': None,
                              'src_file': None,
                              'binary': binary, 
                              'line': None,
                              'offset': None,
                              'build_id': None,
                              'signature': signature})
            elif any(binary.endswith(ext) for ext in ['.c', '.cpp', '.h', '.hpp']):
                trace.append({'depth': depth, 
                              'func_name': None,
                              'type': 'source', 
                              'src_loc': f"{binary}:0", 
                              'src_file': binary, 
                              'binary': None,
                              'line': 0, 
                              'offset': None,
                              'build_id': None,
                              'signature': signature})
            else:
                offset = 0
                try:
                    if '+' in binary:
                        new_binary, offset = binary.split('+')
                        offset = int(offset, 0)
                        binary = new_binary
                except:
                    offset = 0

                trace.append({'depth': depth, 
                              'func_name': None,
                              'type': 'binary', 
                              'src_loc': None,
                              'src_file': None,
                              'binary': binary, 
                              'line': None,
                              'offset': offset, 
                              'build_id': None,
                              'signature': signature})
        else:
            raise RuntimeError(f"Fail to parse stack_trace: {stack_trace}")

    # derive function name from the function signature
    for x in trace:
        signature = x['signature']
        res = re.search(r'\(.*\)$', signature)
        if not res:
            x['func_name'] = signature
        else:
            x['func_name'] = signature[:-len(res.group(0))]

    return trace

class CrashContext:
    def __init__(self, run_pov_metadata):
        self.run_pov_metadata = run_pov_metadata
        self.crash_type = None
        self.internal_crash_type = None
        self.stack_traces = None
        self.sanitizer = None

        self._report = None

    @property
    def final_crash_type(self):
        if self.internal_crash_type == None: 
            return self.crash_type
        return self.internal_crash_type
        
    @property
    def final_sanitizer_type(self):
        return self.sanitizer + ": " + self.crash_type

    def collect(self):
        # 
        self._report = self._extract_report(self.run_pov_metadata)
        if self._report:
            self._parse_report()

    @staticmethod
    def _extract_report(run_pov_metadata):
        outs = run_pov_metadata['run_pov_result']['stdout']
        errs = run_pov_metadata['run_pov_result']['stderr']
        if type(outs) is str:
            outs = outs.encode()
        if type(errs) is str:
            errs = errs.encode()

        # print(outs.decode('latin-1'))
        # print(errs.decode('latin-1'))
        # idx = errs.find(SEPARATOR)
        if (idx := errs.find(b'==WARNING: ')) >= 0:
            report = errs[idx:].decode().strip()
        elif (idx := errs.find(b'==ERROR: ')) >= 0:
            report = errs[idx:].decode().strip()
        elif (idx := errs.find(b'== ERROR: ')) >= 0:
            # 
            report = errs[idx:].decode().strip()
        elif (idx := errs.find(SEPARATOR)) >= 0:
            report = errs[idx+len(SEPARATOR):].decode().strip()
        elif (idx := errs.find(b'UndefinedBehaviorSanitizer:DEADLYSIGNAL')) >= 0:
            report = errs[idx+len(b'UndefinedBehaviorSanitizer:DEADLYSIGNAL'):].decode().strip()
        elif (idx := errs.find(b'MemorySanitizer:DEADLYSIGNAL')) >= 0:
            report = errs[idx+len(b'MemorySanitizer:DEADLYSIGNAL'):].decode().strip()
        
        elif (idx := errs.find(b'MemorySanitizer: CHECK failed')) >= 0:
            report = errs[idx:].decode().strip()

        elif match := re.search(b'.*: runtime error: .*', errs):
            report = errs[errs.find(b'runtime error: '):].decode().strip()

        else:
            
            print("Fail to find the separator in the stderr")
            return None
        
        return report

    def _parse_report(self):
        """
        crash_type: memory-leak, null-ptr-deref, wild-ptr-deref
        """
        io = StringIO(self._report)

        # extract sanitizer type and crash type
        line = io.readline()
        if '==ERROR: ' in line:
            line = line.split('==ERROR: ')[1]
        elif '== ERROR: ' in line:
            line = line.split('== ERROR: ')[1]
        elif '==WARNING: ' in line:
            line = line.split('==WARNING: ')[1]
        self.sanitizer = line.split(':')[0].strip()
        if self.sanitizer != 'runtime error':
            self.sanitizer = self.sanitizer.split()[0]
        match self.sanitizer:
            case 'LeakSanitizer':
                crash_type  = line.split(':')[-1].strip()
                assert crash_type == 'detected memory leaks'
                self.crash_type = 'memory-leak'
            case 'AddressSanitizer':
                if ': attempting double-free' in line:
                    crash_type = 'double-free'
                elif ': attempting free on address which was not malloc()-ed' in line:
                    crash_type = 'bad-free'
                elif ': bad parameters to __sanitizer_' in line:
                    crash_type = 'bad-sanitizer-parameters'
                elif 'AddressSanitizer failed to allocate' in line:
                    crash_type = 'out-of-memory'
                else:
                    crash_type  = line.split('AddressSanitizer: ')[1].split(':')[0].strip().split()[0]
                self.crash_type = crash_type
            case 'MemorySanitizer':
                crash_type  = line.split("MemorySanitizer: ")[1].split(':')[0].strip()
                if crash_type != 'CHECK failed':
                    crash_type = crash_type.split()[0]
                self.crash_type = crash_type
            case 'UndefinedBehaviorSanitizer':
                crash_type = line.split("UndefinedBehaviorSanitizer: ")[1].split()[0].strip()
                self.crash_type = crash_type
            case 'runtime error':
                assert 'UndefinedBehaviorSanitizer' in self._report
                self.sanitizer = 'UndefinedBehaviorSanitizer'
                if match := re.search(r'SUMMARY: UndefinedBehaviorSanitizer: ([0-9a-zA-Z-]+) ', self._report):
                    self.crash_type = match.group(1)
                else:
                    
                    raise NotImplementedError(f"Unknown sanitizer {self.sanitizer}")
            case 'libFuzzer':
                self.sanitizer = 'libFuzzer'
                self.crash_type = line.split('libFuzzer:')[1].strip().split('(')[0].strip()
            case _:
                print(line)
                
                raise NotImplementedError(f"Unknown sanitizer {self.sanitizer}")
        
        
        # self.sanitizer = self.sanitizer + ": " + self.crash_type
        if self.crash_type == 'SEGV':
            assert 'unknown address' in line
            address = line[line.index('unknown address')+len('unknown address'):].strip().split()[0]
            if 'unknown address (pc' not in line:
                addr = int(address, 16)
                if addr == 0:
                    crash_type = 'null-ptr-deref'
                else:
                    crash_type = 'wild-ptr-deref'
            else:
                crash_type = 'wild-ptr-deref'
            self.internal_crash_type = crash_type

        #print(line, [self.sanitizer], [self.crash_type])

        # extract the stack traces and summary
        traces = []
        trace = ''
        while True:
            line = io.readline()
            if not line:
                break
            line = line.lstrip(' ')
            trace += line
            if line == '\n':
                traces.append(trace.strip())
                trace = ''
        self.summary = trace

        # categorize stack traces
        stack_traces = {}
        traces = [x for x in traces if x.strip() and '#0' in x]
        stack_traces['main'] = traces[0] if len(traces) >= 1 else ''
        match self.crash_type:
            case 'memory-leak' | 'null-ptr-deref' | 'wild-ptr-deref' | 'global-buffer-overflow' | 'stack-overflow' | \
                    'SEGV' | 'CHECK failed' | 'undefined-behavior' | 'unknown-crash' | 'out-of-memory' | \
                    'fuzz target overwrites its const input' | 'fuzz target exited' | 'bad-sanitizer-parameters':
                pass
            case 'heap-buffer-overflow' | 'container-overflow' | 'use-after-poison' | 'memcpy-param-overlap' | 'negative-size-param':
                stack_traces['allocate'] = traces[1] if len(traces) >= 2 else ''
            case 'heap-use-after-free' | 'double-free':
                stack_traces['free'] = traces[1] if len(traces) >= 2 else ''
                stack_traces['allocate'] = traces[2] if len(traces) >= 3 else ''
            case 'stack-buffer-overflow' | 'bad-free' | 'stack-use-after-return' | 'stack-use-after-scope' | 'stack-buffer-underflow':
                stack_traces['crashing-address-frame'] = traces[1] if len(traces) >= 2 else ''
                stack_traces['frame-info'] = traces[2] if len(traces) >= 3 else ''
            case 'dynamic-stack-buffer-overflow':
                stack_traces['crashing-address-frame'] = traces[1] if len(traces) >= 2 else ''
            case 'use-of-uninitialized-value':
                # stack_traces['uninitialized-value-creation'] = traces[1] if len(traces) >= 3 else ''
                stack_traces['uninitialized-value-allocation'] = traces[-2] if len(traces) >= 3 else ''

            case 'unknown-crash' | 'deadly signal':
                stack_traces['main'] = traces[0] if len(traces) >= 1 else ''

            case _:

                
                print(self.crash_type)
                print(traces)
                raise NotImplementedError(f"Unknown crash_type {self.crash_type}")

        # extract crash action
        line = stack_traces['main']
        self.crash_action = {}
        if line:
            elems = line.split()
            match self.sanitizer:
                case 'LeakSanitizer':
                    self.crash_action["access"] = elems[1].lower()
                    self.crash_action["size"] = int(elems[elems.index('of')+1])
                case 'libFuzzer':
                    if self.crash_type == 'fuzz target overwrites its const input':
                        self.crash_action["access"] = 'WRITE'
                        self.crash_action["size"] = 'unknown'
                    elif self.crash_type in ['deadly signal', 'out-of-memory', 'fuzz target exited']:
                        self.crash_action['access'] = 'unknown'
                        self.crash_action['size'] = 'unknown'
                    else:
                        
                        raise NotImplementedError(f"Unknown sanitizer {self.sanitizer}")
                case 'AddressSanitizer':
                    if self.crash_type in ['null-ptr-deref', 'wild-ptr-deref', 'SEGV']:
                        self.crash_action["access"] = elems[elems.index('a')+1]
                        self.crash_action["size"] = 'unknown'
                    elif self.crash_type in ['stack-overflow', 'double-free', 'bad-free', 'out-of-memory',
                                             'memcpy-param-overlap', 'negative-size-param', 'bad-sanitizer-parameters']:
                        self.crash_action["access"] = 'unknown'
                        self.crash_action["size"] = 'unknown'
                    elif self.crash_type in [
                        'heap-buffer-overflow', 'stack-buffer-overflow', 'heap-use-after-free', 'stack-use-after-return',
                        'use-after-poison', 'global-buffer-overflow', 'container-overflow', 'unknown-crash',
                        'stack-use-after-scope', 'dynamic-stack-buffer-overflow', 'stack-buffer-underflow'
                        ]:
                        self.crash_action["access"] = elems[0].lower()
                        self.crash_action["size"] = int(elems[elems.index('size')+1])
                    else:
                        # 
                        raise NotImplementedError(f"Unknown sanitizer {self.sanitizer}")
                case 'UndefinedBehaviorSanitizer':
                    if self.crash_type in ['SEGV']:
                        self.crash_action["access"] = elems[elems.index('a')+1]
                        self.crash_action["size"] = 'unknown'
                    elif self.crash_type in ['undefined-behavior']:
                        self.crash_action["access"] = 'unknown'
                        self.crash_action["size"] = 'unknown'
                    else:
                        
                        raise NotImplementedError(f"Unknown sanitizer {self.sanitizer}")

                case "MemorySanitizer":
                    if self.crash_type in ['CHECK failed', 'use-of-uninitialized-value']:
                        self.crash_action['access'] = 'unknown'
                        self.crash_action['size'] = 'unknown'
                    elif self.crash_type in ['SEGV']:
                        self.crash_action["access"] = elems[elems.index('a')+1]
                        self.crash_action["size"] = 'unknown'
                    else:
                        
                        raise NotImplementedError(f"Unknown sanitizer {self.sanitizer}")
                        
                case _:
                    print(line)
                    raise NotImplementedError(f"Unknown sanitizer {self.sanitizer}")

            #print(self.crash_action)

        # further parse stack_trace
        self.stack_traces = {k: parsed_stack_trace(v) for k, v in stack_traces.items()}

def create_asan_report(pov_metadata):
    ctx = CrashContext(pov_metadata)
    ctx.collect()

    consistent_sanitizers = pov_metadata['consistent_sanitizers']
    inconsistent_sanitizers = pov_metadata['inconsistent_sanitizers']
    sanitizer_history = pov_metadata['sanitizer_history']

    fancy = {
        # pydatatask things
        "project_id": str(pov_metadata['project_id']),
        "harness_info_id": pov_metadata['harness_info_id'],
        "crash_report_id": pov_metadata['crash_report_id'],

        "consistent_sanitizers": consistent_sanitizers,
        "inconsistent_sanitizers": inconsistent_sanitizers,
        "sanitizer_history": sanitizer_history,
        
        # cp things
        "cp_harness_id": pov_metadata['cp_harness_id'],
        "cp_harness_name": pov_metadata['cp_harness_name'],
        "cp_harness_binary_path": pov_metadata['cp_harness_binary_path'],
        "cp_harness_source_path": pov_metadata['cp_harness_source_path'],

        # nice to know
        "fuzzer": pov_metadata['fuzzer'],

        "sanitizer": ctx.final_sanitizer_type,
        "crash_type": ctx.final_crash_type,
        "stack_traces": ctx.stack_traces,
    }
    return fancy

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("crash_run_pov_metadata")
    parser.add_argument("asan_report_parsed_output")
    args = parser.parse_args()
    with open(args.crash_run_pov_metadata) as f:
        pov_metadata = yaml.safe_load(f)

    log.info("Creating ASAN report for %s", pov_metadata)
    if 'run_pov_result' in pov_metadata:
        if 'stderr' in pov_metadata and type(pov_metadata) is str:
            pov_metadata['run_pov_result']['stderr'] = pov_metadata['run_pov_result']['stderr'].encode()
        if 'stdout' in pov_metadata and type(pov_metadata) is str:
            pov_metadata['run_pov_result']['stdout'] = pov_metadata['run_pov_result']['stdout'].encode()
    
    fancy = create_asan_report(pov_metadata)

    validated_data = json.loads(ASANReport(**fancy).model_dump_json())
    log.info("Dumping ASAN report: %s", validated_data)
    with open(args.asan_report_parsed_output, "w") as f:
        yaml.dump(validated_data, f)

