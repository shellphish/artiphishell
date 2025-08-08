ARG BASE_IMAGE=
ARG PREBUILD_IMAGE=

# pull the prebuild image in with a given name
FROM ${PREBUILD_IMAGE} AS prebuild
FROM ${BASE_IMAGE} as jazzer_base_build


RUN mkdir -p /shellphish

# For Jazzer in out
COPY wrapper.py /shellphish/wrapper.py
RUN chmod +x /shellphish/wrapper.py

COPY symlink_patch /shellphish/symlink_patch
RUN cat /shellphish/symlink_patch >> /usr/local/bin/compile

# Copy jazzer from prebuild
RUN mkdir -p $SRC/shellphish/jazzer-aixcc/jazzer-build/
RUN mkdir -p $OUT/shellphish/jazzer-aixcc/jazzer-build/

COPY --from=prebuild $SRC/shellphish/jazzer-aixcc/jazzer-build/jazzer_driver $SRC/shellphish/jazzer-aixcc/jazzer-build/jazzer_driver
COPY --from=prebuild $SRC/shellphish/jazzer-aixcc/jazzer-build/jazzer_agent_deploy.jar $SRC/shellphish/jazzer-aixcc/jazzer-build/jazzer_agent_deploy.jar

# Copy nautilus from prebuild
RUN mkdir -p $SRC/shellphish/nautilus
COPY --from=prebuild $SRC/shellphish/nautilus/librevolver_mutator.so $SRC/shellphish/nautilus
COPY --from=prebuild $SRC/shellphish/nautilus/watchtower $SRC/shellphish/nautilus
# COPY --from=prebuild $SRC/nautilus/target/release/generator $SRC/shellphish/nautilus

