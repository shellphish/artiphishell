# poiguy

### poiguy local runs
* codeql ``` python poiguyrun.py --target <id> --scanner codeql --scan_report_dir <> --joern_db <> --poi_normalized_dir <> ```
* semgrep ``` python poiguyrun.py --target <id> --scanner semgrep --scan_report_dir <> --joern_db <> --poi_normalized_dir <> ```
* joern ``` python poiguyrun.py --target <id> --scanner joern --scan_report_dir <> --poi_normalized_dir <>```
* mango ``` python poiguyrun.py --target <id> --scanner mango --scan_report_dir <> --poi_normalized_dir <> ```
* ddfq ```  python poiguyrun.py --target <id> --scanner ddfa --scan_report_dir <> --poi_normalized_dir <> ```
* opwnai audit ```  python poiguyrun.py --target <id> --scanner opwnaiaudit --scan_report_dir <> --poi_normalized_dir <> ```
### poiguy PyDataTask Run
```./build_and_run_poi_guy.sh ```

### Data Parsing Outputs

#### CodeQL and Semgrep
```
scanner: <semgrep><codeql>
target: hamlin
vuln_code_line: '      delete c;'
vuln_description: The software attempts to return a memory resource to the system,
  but it calls a release function that is not compatible with the function that was
  originally used to allocate that resource. Due to inherent limitations of Semgrep,
  this rule might generate many false positives and should therefore be customized
  for your codebase.
vuln_file: ../../hamlin/challenge_src/src/png/chunk_factory.cpp
vuln_function: materialize_chunks
vuln_level: warning
vuln_line: 110
vuln_rule: rules.c.security_1.raptor-mismatched-memory-management-cpp
vuln_rule_description: The software attempts to return a memory resource to the system,
  but it calls a release function that is not compatible with the function that was
  originally used to allocate that resource. Due to inherent limitations of Semgrep,
  this rule might generate many false positives and should therefore be customized
  for your codebase.
vuln_source: static analysis

```

#### Joern
```
scanner: joern
target: hamlin
vuln_description: Dangerous function gets() used
vuln_function: main
vuln_line: 7
vuln_source: static analysis
```

#### Mango
```
scanner: mango
target: hamlin
vuln_description: 'file:"/tmp/pydatatask-twosutrj-10721038181541653880/challenge_src/./src/parser.cpp"
  line:"1124" function:"yyparse()"

  file:"/tmp/pydatatask-twosutrj-10721038181541653880/challenge_src/./src/parser.cpp"
  line:"1231" function:"malloc"

  file:"/tmp/pydatatask-twosutrj-10721038181541653880/challenge_src/./src/parser.cpp"
  line:"1234" function:"memcpy"

  file:"/tmp/pydatatask-twosutrj-10721038181541653880/challenge_src/./src/parser.cpp"
  line:"1235" function:"memcpy"'
vuln_function: memcpy
vuln_line: 1235
vuln_source: static analysis
```

#### DDFA
```
scanner: ddfa
target: hamlin
vuln_description: ddfa detected True
vuln_file: png/ihdr.hpp
vuln_function: ~Ihdr
vuln_line: 25
vuln_source: static analysis

```

#### Opwnai Audit Function
```
scanner: opwnaiaudit
target: target
vuln_description: The get_filter function may lead to undefined behavior if it receives
  an invalid filter_sigil byte that doesn't map to an existing filter type. In release
  builds, where assert could be stripped off, this might execute whatever code lies
  beyond the switch-case. This issue could result in potential security vulnerabilities
  if the function is exposed to unchecked user inputs. Therefore, proper input validation
  where get_filter function is called is necessary to avoid these potential risks.
vuln_function: png.filter.get_filter
vuln_line: 'default: assert(false);'
vuln_source: Gpt Auditing
vuln_type: Unchecked user input leading to undefined behavior
```

### ASAN
```
target: test
scanner: asan
vuln_file: /tmp/pydatatask-rjofmwed-output-srcResults-1/challenge_src/src/deflate/array_history.cpp
vuln_function: deflate::ArrayHistory::copy(unsigned int, unsigned short)
vuln_description: heap-buffer-overflow
vuln_level: null
vuln_line: 28
vuln_code_line: operator new(unsigned long)
vuln_rule: AddressSanitizer
vuln_rule_description: null
vuln_source: dynamic analysis
meta:
  crash_action:
    access: read
    size: 1
  crash_input: /tmp/pydatatask-kwyjbelg-input-crash_input-5678
  crash_type: heap-buffer-overflow
  sanitizer: AddressSanitizer
  stacktrace-allocate:
  - binary: /tmp/pydatatask-rmjjdmxe-input-target_asan_binary-1/hamlin.bin
    build_id: 6d7ca617b8baaeff24d26526c4d478c89da3b5f1
    depth: 0
    func_name: operator new
    offset: 984957
    signature: operator new(unsigned long)
    type: binary
  - depth: 1
    func_name: Inflate::Inflate
    line: 22
    signature: Inflate::Inflate(deflate::ZlibHeader, deflate::BitVector&)
    src_file: /tmp/pydatatask-rjofmwed-output-srcResults-1/challenge_src/src/inflate.cpp
    type: source
  - depth: 2
    func_name: Png::Png
    line: 24
    signature: Png::Png(std::istream&)
    src_file: /tmp/pydatatask-rjofmwed-output-srcResults-1/challenge_src/src/png.cpp
    type: source
  - depth: 3
    func_name: main
    line: 104
    signature: main
    src_file: /tmp/pydatatask-rjofmwed-output-srcResults-1/challenge_src/src/main.cpp
    type: source
  stacktrace-function:
  - depth: 0
    func_name: deflate::ArrayHistory::copy
    line: 28
    signature: deflate::ArrayHistory::copy(unsigned int, unsigned short)
    src_file: /tmp/pydatatask-rjofmwed-output-srcResults-1/challenge_src/src/deflate/array_history.cpp
    type: source
  - depth: 1
    func_name: Inflate::inflate_code
    line: 149
    signature: Inflate::inflate_code(deflate::Code&, deflate::DistanceCode&)
    src_file: /tmp/pydatatask-rjofmwed-output-srcResults-1/challenge_src/src/inflate.cpp
    type: source
  - depth: 2
    func_name: Inflate::inflate_fixed
    line: 84
    signature: Inflate::inflate_fixed()
    src_file: /tmp/pydatatask-rjofmwed-output-srcResults-1/challenge_src/src/inflate.cpp
    type: source
  - depth: 3
    func_name: Inflate::inflate
    line: 54
    signature: Inflate::inflate()
    src_file: /tmp/pydatatask-rjofmwed-output-srcResults-1/challenge_src/src/inflate.cpp
    type: source
  - depth: 4
    func_name: Inflate::inflated
    line: 31
    signature: Inflate::inflated()
    src_file: /tmp/pydatatask-rjofmwed-output-srcResults-1/challenge_src/src/inflate.cpp
    type: source
  - depth: 5
    func_name: png::ImageCoder::load_image_data
    line: 25
    signature: png::ImageCoder::load_image_data(std::vector<unsigned char, std::allocator<unsigned
      char>>, png::Ihdr, png::Plte*)
    src_file: /tmp/pydatatask-rjofmwed-output-srcResults-1/challenge_src/src/png/image_coder.cpp
    type: source
  - depth: 6
    func_name: Png::Png
    line: 24
    signature: Png::Png(std::istream&)
    src_file: /tmp/pydatatask-rjofmwed-output-srcResults-1/challenge_src/src/png.cpp
    type: source
  - depth: 7
    func_name: main
    line: 104
    signature: main
    src_file: /tmp/pydatatask-rjofmwed-output-srcResults-1/challenge_src/src/main.cpp
    type: source
  - binary: /lib/x86_64-linux-gnu/libc.so.6
    build_id: a43bfc8428df6623cd498c9c0caeb91aec9be4f9
    depth: 9
    func_name: __libc_start_main
    offset: 171583
    signature: __libc_start_main
    type: binary
  - binary: /tmp/pydatatask-rmjjdmxe-input-target_asan_binary-1/hamlin.bin
    build_id: 6d7ca617b8baaeff24d26526c4d478c89da3b5f1
    depth: 10
    func_name: _start
    offset: 207716
    signature: _start
    type: binary
  target: /tmp/pydatatask-rmjjdmxe-input-target_asan_binary-1/hamlin.bin
```

### illmutable

```
scanner: illmutable
target: '1'
vuln_code_line: "@WebMethod(name = \"heapdump.hprof\")\npublic void doHeapDump(StaplerRequest\
  \ req, StaplerResponse rsp) throws IOException, InterruptedException {\n    owner.checkPermission(Jenkins.ADMINISTER);\n\
  \    rsp.setContentType(\"application/octet-stream\");\n    FilePath dump = obtain();\n\
  \    try {\n        dump.copyTo(rsp.getCompressedOutputStream(req));\n    } finally\
  \ {\n        dump.delete();\n    }\n}"
vuln_description: '

  This endpoint is likely vulnerable to a CSRF attack. The route appears reachable
  via a GET request.

  It looks like the actions performed by this endpoint are state changing when attacking
  a privileged user. To patch, you probably want to add `@RequirePOST` annotation
  to the `hudson.util.RemotingDiagnostics.HeapDump.doHeapDump` method.


  Analysis of dangerous actions performed by the source code: `Creating a heap dump
  alters server state via resource allocation and usage, and even though direct sensitive
  data leakage to an attacker is not possible, the process itself could be triggered
  maliciously.`

  '
vuln_file: fa9ea93b610359a9efe4c61b743f00360d1462cb/./core/src/main/java/hudson/util/RemotingDiagnostics.java
vuln_function: hudson.util.RemotingDiagnostics.HeapDump.doHeapDump(org.kohsuke.stapler.StaplerRequest,org.kohsuke.stapler.StaplerResponse)
vuln_line: 198
vuln_source: static analysis + LLM
vuln_type: 'CWE-352: Cross-Site Request Forgery (CSRF)'

```
