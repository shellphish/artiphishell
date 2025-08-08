ARG BASE_IMAGE=
ARG PREBUILD_IMAGE=

# pull the prebuild image in with a given name
FROM ${PREBUILD_IMAGE} AS prebuild

FROM ${BASE_IMAGE} AS final-builder

RUN echo 1
RUN apt-get update && apt-get install -y gcc g++
RUN apt-get update && \
    apt-get install -y \
    build-essential \
    gcc-9-plugin-dev \
    libstdc++-9-dev \
    patchelf

RUN mv /usr/bin/ld /usr/bin/ld.real
COPY anti-wrap-ld.sh /usr/bin/ld
RUN chmod +x /usr/bin/ld

RUN mkdir -p $SRC/shellphish
COPY --from=prebuild  $SRC/shellphish/aflplusplus $SRC/shellphish/aflplusplus
# COPY aflpp_patch/dewrap* $SRC/shellphish/aflplusplus/instrumentation/
# RUN ls -al /afl && cd /afl && git apply $SRC/shellphish/aflplusplus/instrumentation/dewrap_patch.diff
RUN cat $SRC/shellphish/aflplusplus/src/afl-fuzz-run.c | grep "SHELLPHISH"

RUN mkdir -p $SRC/shellphish/nautilus
COPY --from=prebuild $SRC/nautilus/target/release/librevolver_mutator.so $SRC/shellphish/nautilus
COPY --from=prebuild $SRC/nautilus/target/release/watchtower $SRC/shellphish/nautilus
COPY --from=prebuild $SRC/nautilus/target/release/generator $SRC/shellphish/nautilus

COPY compile_shellphish_aflpp /usr/local/bin/
