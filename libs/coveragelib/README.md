# Coveragelib

<img width="1212" alt="Screenshot 2025-03-13 at 4 03 31 PM" src="https://github.com/user-attachments/assets/5fc7ba86-dc3d-423c-adab-7d9a4ff61084" />

This library allows to collect and parse coverage information for a given seed (C, Java).

To use this library, we need the build done by `coverage-guy:coverage_build` https://github.com/shellphish-support-syndicate/artiphishell/blob/feat/oss-fuzz--new-beginnings/components/coverage-guy/pipeline_build.yaml#L56


If you are just debugging in your environment, you can get that build by
doing:

```bash
oss-fuzz-build <TARGET_FOLDER> --sanitizer coverage --instrumentation coverage_fast --architecture x86_64
```

### Example 1

By default, the parser being used is the `SimpleProfrawParser` for `C` and the `SimpleJacocoParser` for `Java`.

```python
from coveragelib import Tracer
with Tracer("/shared/tests/oss-fuzz-projects/nginx", "http_request_fuzzer") as tracer:
  tracer.trace("/path/to/your/seed")
```

### Example 2

If you want to use a different parser:


```python
from coveragelib import Tracer
from coveragelib.cparse import LLVMCovHTMLCoverageReportParser

with Tracer("/shared/tests/oss-fuzz-projects/nginx", "http_request_fuzzer", parser=LLVMCovHTMLCoverageReportParser()) as tracer:
  tracer.trace("/path/to/your/seed")
```
