ARG BASE_IMAGE=
FROM ${BASE_IMAGE} AS aflpp-afl-compile-base


# FIXME: I need to install llvm to have llvm-dwarfdump available
RUN apt-get update && apt-get install -y gdbserver socat strace jq llvm


RUN mkdir -p $SRC/shellphish
RUN mkdir -p $SRC/shellphish/pintracer 

# We built the new coverage script based on the one 
# at https://github.com/aixcc-finals/oss-fuzz-aixcc/blob/master/infra/base-images/base-runner/coverage
# commit: 8bc2e0b5cfeffaee2cd8f6dd27e0b72ca87bac88.
# So, if anything changes there, we want to know: Check md5sum before starting.
RUN md5sum /usr/local/bin/coverage > ./coverage.md5sum 2>&1 
RUN cat ./coverage.md5sum
# Check if the md5sum of the coverage script matches the expected value a8f56f76b7949a8333e605aa3dfd3344
RUN grep "a8f56f76b7949a8333e605aa3dfd3344" ./coverage.md5sum || { echo "Error: The specified line was not found in coverage.md5sum | ping @degrigis"; exit 1; }

# oss-fuzz-coverage is our modified coverage bash script
COPY oss-fuzz-coverage /usr/local/bin/
# The oss-fuzz-coverage_live is basically keeping the coverage container up and trace every seed appearing in the 
# monitored folder
COPY oss-fuzz-coverage_live /usr/local/bin/

# coverage is our wrapper that decides between watchdog or not
COPY coverage /usr/local/bin/

RUN chmod +x /usr/local/bin/coverage
RUN chmod +x /usr/local/bin/oss-fuzz-coverage
RUN chmod +x /usr/local/bin/oss-fuzz-coverage_live

ENV PIN_ROOT $OUT/pin

COPY ./pintool-tracer/pintool-json-calls.sh /usr/local/bin/pintool-json-calls.sh
COPY ./pintool-tracer/pintool-json-inds.sh /usr/local/bin/pintool-json-inds.sh
COPY ./pintool-tracer/get-inlines.sh /usr/local/bin/get-inlines.sh
COPY ./pintool-tracer/extract-pointers.py /usr/local/bin/extract-pointers.py
COPY ./pintool-tracer/dwarf_inlined_parser /usr/local/bin/dwarf_inlined_parser

RUN chmod +x /usr/local/bin/pintool-json-calls.sh
RUN chmod +x /usr/local/bin/pintool-json-inds.sh
RUN chmod +x /usr/local/bin/get-inlines.sh
RUN chmod +x /usr/local/bin/extract-pointers.py
RUN chmod +x /usr/local/bin/dwarf_inlined_parser