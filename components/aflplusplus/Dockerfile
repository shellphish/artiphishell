# aixcc-build: aixcc-aflplusplus

ARG IMAGE_PREFIX=
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell

FROM ${IMAGE_PREFIX}aixcc-component-base as aflpp-base
LABEL org.opencontainers.image.source=${SOURCE_REPO}


FROM gcr.io/oss-fuzz-base/base-clang@sha256:67cbcf99b475da7268d8258aa11f711a9d243174a04d84296c16556dc98eaf0f as aflpp-afl-compile-base

RUN apt-get update && apt-get install -y gcc g++
RUN apt-get update && \
    apt-get install -y \
    build-essential \
    python3-dev \
    automake \
    cmake \
    git \
    flex \
    bison \
    libglib2.0-dev \
    libpixman-1-dev \
    python3-setuptools \
    cargo \
    libgtk-3-dev \
    gcc-9-plugin-dev \
    libstdc++-9-dev \
    ninja-build
RUN apt-get update && apt-get install -y patchelf

RUN git clone https://github.com/AFLplusplus/AFLplusplus /afl
RUN sed 's/void sync_fuzzers(afl_state_t \*afl) {/void sync_fuzzers(afl_state_t \*afl) { printf("SHELLPHISH: sync\\n"); /' -i /afl/src/afl-fuzz-run.c
RUN sed 's/\(if (likely(!afl->stop_soon && afl->sync_id)) {\)/printf("SHELLPHISH: pre-sync: afl->is_main_node: %d, afl->sync_time: %d\n"); \1/' -i /afl/src/afl-fuzz-run.c
# COPY aflpp_patch/dewrap* /afl/instrumentation/
# RUN ls -al /afl && cd /afl && git apply /afl/instrumentation/dewrap_patch.diff
RUN cat /afl/src/afl-fuzz-run.c | grep "SHELLPHISH"

RUN cd /afl && unset CFLAGS CXXFLAGS && \
    export CC=clang CXX=clang++ && \
    export REAL_CC=gcc REAL_CXX=g++ && \
    export AFL_NO_X86=1 NO_NYX=1 && \
    sed -i 's/-Wno-deprecated-copy-with-dtor//g' ./GNUmakefile.llvm && \
    LLVM_CONFIG=$(which llvm-config) STATIC=1 PYTHON_INCLUDE=/ make source-only
# RUN ls -al --color=yes /afl && exit 1
# RUN find /afl -name 'cmplog*.so*' && exit 1

RUN cd /afl && PREFIX=/opt/afl make install
RUN cp /afl/*.o /opt/afl/bin/
RUN cp /afl/*.so /opt/afl/bin/
RUN cp /afl/*.a /opt/afl/bin/
RUN cp /afl/afl-* /opt/afl/bin/
RUN cp /afl/dynamic_list.txt /opt/afl/bin/
# RUN cp /afl/afl-as /opt/afl/bin/as

COPY --from=aflpp-base /shellphish/libs/libfreedom /shellphish/libs/libfreedom
RUN /shellphish/libs/libfreedom/dump_deps.sh /opt/afl/bin/* /usr/lib/x86_64-linux-gnu/libstdc++.so.6 /usr/lib/gcc/x86_64-linux-gnu/9/libstdc++.so

FROM aflpp-base as aflpp-base-2

COPY --from=aflpp-afl-compile-base /shellphish/libs/libfreedom /shellphish/libs/libfreedom

FROM gcr.io/oss-fuzz-base/base-clang@sha256:67cbcf99b475da7268d8258aa11f711a9d243174a04d84296c16556dc98eaf0f as test
COPY --from=aflpp-base-2 /shellphish/libs/libfreedom /shellphish/libs/libfreedom
ENV AFL_DEBUG=1
ENV AFL_CC=clang
ENV AFL_CXX=clang++
ENV LIBRARY_PATH=/shellphish/libs/libfreedom/bin/:$LIBRARY_PATH
ENV AFL_LLVM_INSTRUMENT=pc-guard
RUN echo hi && \
    echo '#include <stdio.h>' > empty.cpp && \
    echo 'int main() { if (getchar() == 69) printf("Noice.\\n"); }' >> empty.cpp && \
    /shellphish/libs/libfreedom/bin/afl-clang-fast empty.cpp -o empty && \
    /shellphish/libs/libfreedom/bin/afl-clang-fast++ empty.cpp -o empty

FROM aflpp-base-2 as aflpp
COPY --from=test /empty /empty
# RUN chmod +x /fuzz.sh && chmod +x /sync_inputs.sh

RUN mkdir -p /aflplusplus/
COPY ./aflplusplus_modifications/ /shellphish/aflpp/
COPY ./run_scripts/ /shellphish/aflpp/run_scripts/

WORKDIR /afl

ENV PATH=${PATH}:/shellphish/aflpp/


ENTRYPOINT [ "/bin/bash", "-c" ]
