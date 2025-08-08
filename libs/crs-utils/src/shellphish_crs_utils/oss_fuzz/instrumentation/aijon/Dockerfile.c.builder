ARG BASE_IMAGE=
FROM ghcr.io/aixcc-finals/base-builder:v1.0.0 AS aijon-afl-compile-base

RUN apt-get update && apt-get install -y gcc g++
RUN apt-get update && \
    apt-get install -y \
    build-essential \
    automake \
    cmake \
    git \
    flex \
    bison \
    libglib2.0-dev \
    libpixman-1-dev \
    python3-setuptools \
    libgtk-3-dev \
    gcc-9-plugin-dev \
    libstdc++-9-dev \
    ninja-build
RUN apt-get update && apt-get install -y patchelf

RUN mkdir -p $SRC/shellphish
RUN git clone -b v4.30c  https://github.com/AFLplusplus/AFLplusplus $SRC/shellphish/aflplusplus
RUN sed 's/void sync_fuzzers(afl_state_t \*afl) {/void sync_fuzzers(afl_state_t \*afl) { printf("SHELLPHISH: sync\\n"); /' -i $SRC/shellphish/aflplusplus/src/afl-fuzz-run.c
RUN sed 's/\(if (likely(!afl->stop_soon && afl->sync_id)) {\)/printf("SHELLPHISH: pre-sync: afl->is_main_node: %d, afl->sync_time: %d\n"); \1/' -i $SRC/shellphish/aflplusplus/src/afl-fuzz-run.c
COPY aflpp.diff /tmp/aflpp.diff
RUN cd $SRC/shellphish/aflplusplus && git apply /tmp/aflpp.diff

COPY precompile_shellphish_aijon /usr/local/bin/
RUN precompile_shellphish_aijon || (cat "$SRC/shellphish/aflplusplus/utils/aflpp_driver/aflpp_driver.c" && exit 1)

# Make SURE the aflpp_driver.o has the symbols
RUN strings $SRC/shellphish/aflplusplus/utils/aflpp_driver/aflpp_driver.o | grep "##SIG_AFL_PERSISTENT##"
RUN strings $SRC/shellphish/aflplusplus/utils/aflpp_driver/aflpp_driver.o | grep "##SIG_AFL_DEFER_FORKSRV##"

FROM ${BASE_IMAGE} AS final-builder

RUN mv /usr/bin/ld /usr/bin/ld.real
COPY anti-wrap-ld.sh /usr/bin/ld
RUN chmod +x /usr/bin/ld

RUN mkdir -p $SRC/shellphish
COPY --from=aijon-afl-compile-base $SRC/shellphish/aflplusplus $SRC/shellphish/aflplusplus
# COPY aflpp_patch/dewrap* $SRC/shellphish/aflplusplus/instrumentation/
# RUN ls -al /afl && cd /afl && git apply $SRC/shellphish/aflplusplus/instrumentation/dewrap_patch.diff
RUN cat $SRC/shellphish/aflplusplus/src/afl-fuzz-run.c | grep "SHELLPHISH"

RUN apt-get update && apt-get install -y gcc g++
RUN apt-get update && \
    apt-get install -y \
    build-essential \
    gcc-9-plugin-dev \
    libstdc++-9-dev

RUN apt-get update && apt-get install -y patchelf

ENV AFL_PATH=$SRC/shellphish/aflplusplus

COPY compile_shellphish_aijon /usr/local/bin/
