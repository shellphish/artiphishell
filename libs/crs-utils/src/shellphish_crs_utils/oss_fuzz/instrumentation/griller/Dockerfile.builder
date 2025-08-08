ARG BASE_IMAGE=
ARG PREBUILD_IMAGE=

# pull the prebuild image in with a given name
FROM ${PREBUILD_IMAGE} AS prebuild

FROM ${BASE_IMAGE} AS final-builder

RUN apt-get update && apt-get install -y python3-pip \
                      python-is-python3 libncurses5 \
                      file cmake pkg-config \
                      protobuf-compiler libc++-dev
RUN pip install wllvm

COPY --from=prebuild /usr/lib/llvm-18 /usr/lib/llvm-18
COPY --from=prebuild /usr/bin/llvm* /usr/bin
COPY --from=prebuild /usr/bin/clang* /usr/bin
COPY --from=prebuild /usr/lib/x86_64-linux-gnu/ /usr/lib/x86_64-linux-gnu/
RUN ln -s /usr/bin/llvm-link-18 /usr/bin/llvm-link

RUN mkdir -p $SRC/shellphish
COPY compile_griller /usr/bin/
COPY generic_harness.c $SRC/shellphish/
COPY anti-wrap-ld.sh $SRC/shellphish/
COPY extract_bc.py /

RUN mv /usr/local/bin/compile /usr/local/bin/compile.old
COPY compile /usr/local/bin/compile
