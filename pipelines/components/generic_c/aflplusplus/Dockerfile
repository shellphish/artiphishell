# aixcc-build: aixcc-aflplusplus

ARG IMAGE_PREFIX=
FROM ${IMAGE_PREFIX}aixcc-dependencies-base as aflpp-base
LABEL org.opencontainers.image.source=https://github.com/aixcc-sc/asc-crs-shellphish

# FROM ubuntu:22.04
RUN apt-get update &&  \
    apt-get upgrade -y && \
    apt-get install -y \
    make \
    autoconf \
    libtool \
    wget \
    build-essential \
    python3-dev \
    python3-setuptools \
    automake \
    cmake \
    git \
    flex \
    bison \
    libglib2.0-dev \
    libpixman-1-dev \
    cargo \
    libgtk-3-dev \
    python-is-python3 \
    python3-pip \
    rsync \
    jq \
    apt-transport-https \
    ca-certificates \
    curl \
    software-properties-common \
    clang-14 clang
RUN apt-get update && apt-get install patchelf strace ltrace htop procps






FROM gcr.io/oss-fuzz-base/base-clang as aflpp-afl-compile-base

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

COPY --from=aflpp-base /shellphish/libfreedom /shellphish/libfreedom
RUN /shellphish/libfreedom/dump_deps.sh /opt/afl/bin/* /usr/lib/x86_64-linux-gnu/libstdc++.so.6 /usr/lib/gcc/x86_64-linux-gnu/9/libstdc++.so

FROM aflpp-base as aflpp-base-2

COPY --from=aflpp-afl-compile-base /shellphish/libfreedom /shellphish/libfreedom

FROM gcr.io/oss-fuzz-base/base-clang as test
COPY --from=aflpp-base-2 /shellphish/libfreedom /shellphish/libfreedom
ENV AFL_DEBUG=1
ENV AFL_CC=clang
ENV AFL_CXX=clang++
ENV LIBRARY_PATH=/shellphish/libfreedom/bin/:$LIBRARY_PATH
ENV AFL_LLVM_INSTRUMENT=pc-guard
RUN echo hi && \
    echo '#include <stdio.h>' > empty.cpp && \
    echo 'int main() { if (getchar() == 69) printf("Noice.\\n"); }' >> empty.cpp && \
    /shellphish/libfreedom/bin/afl-clang-fast empty.cpp -o empty && \
    /shellphish/libfreedom/bin/afl-clang-fast++ empty.cpp -o empty

FROM aflpp-base-2 as aflpp
COPY --from=test /empty /empty
# RUN chmod +x /fuzz.sh && chmod +x /sync_inputs.sh

RUN mkdir -p /aflplusplus/
COPY ./aflplusplus_modifications/ /shellphish/aflpp/

WORKDIR /afl

ENV PATH=${PATH}:/shellphish/aflpp/


ENTRYPOINT [ "/bin/bash", "-c" ]
