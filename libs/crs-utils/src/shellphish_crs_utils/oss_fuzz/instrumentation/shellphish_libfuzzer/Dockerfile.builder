ARG BASE_IMAGE=
ARG PREBUILD_IMAGE=

# pull the prebuild image in with a given name
FROM ${PREBUILD_IMAGE} AS prebuild


FROM ${BASE_IMAGE} as libfuzzer_base_build

COPY --from=prebuild /usr/local/bin/llvm-* /usr/local/bin/
COPY --from=prebuild /usr/local/lib/clang/18/lib/x86_64-unknown-linux-gnu/libclang_rt.fuzzer*.a /usr/local/lib/clang/18/lib/x86_64-unknown-linux-gnu/


# RUN mkdir -p /shellphish

# For Jazzer in out
COPY wrapper.py /shellphish/wrapper.py
RUN chmod +x /shellphish/wrapper.py

COPY symlink_patch /shellphish/symlink_patch
RUN cat /shellphish/symlink_patch >> /usr/local/bin/compile

COPY yq /usr/local/bin/
COPY yq /usr/bin/

# Copy libfuzzer from prebuild
# RUN mkdir -p $SRC/shellphish/jazzer-aixcc/jazzer-build/
# RUN mkdir -p $OUT/shellphish/jazzer-aixcc/jazzer-build/

# Copy nautilus from prebuild
# RUN mkdir -p $SRC/shellphish/nautilus
# COPY --from=prebuild $SRC/shellphish/nautilus/librevolver_mutator.so $SRC/shellphish/nautilus
# COPY --from=prebuild $SRC/shellphish/nautilus/watchtower $SRC/shellphish/nautilus

