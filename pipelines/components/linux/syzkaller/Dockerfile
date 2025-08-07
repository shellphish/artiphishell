# aixcc-build: aixcc-syzkaller


# Start from a base image
ARG IMAGE_PREFIX=

# this stanza replaces what was previously an additional part of the lockstep
FROM ${IMAGE_PREFIX}aixcc-dependencies-base:latest as kernel-build
LABEL org.opencontainers.image.source=https://github.com/aixcc-sc/asc-crs-shellphish

WORKDIR /
ADD ./common /common
RUN ./common/build.sh

FROM ${IMAGE_PREFIX}aixcc-dependencies-base as syzkaller_builder

WORKDIR /shellphish

# Clone and build syzkaller
RUN git clone https://github.com/google/syzkaller
COPY aixcc_syscall_extraction.diff /shellphish/syzkaller
COPY fetch_benign_syzprogs.diff /shellphish/syzkaller
COPY fuzz_through_harness.diff /shellphish/syzkaller
COPY harness.h /shellphish/syzkaller/executor/harness.h
COPY harness.txt /shellphish/syzkaller/sys/linux/harness.txt
RUN cd syzkaller \
    && git checkout e812177 \
    && mkdir -p workdir/crashes \
    && git apply aixcc_syscall_extraction.diff \
    && git apply fetch_benign_syzprogs.diff \
    && git apply fuzz_through_harness.diff \
    && make


FROM ${IMAGE_PREFIX}aixcc-component-base:latest

# Set working directory
WORKDIR /shellphish

COPY --from=kernel-build /image/bullseye.img /kernel/image/
COPY --from=kernel-build /image/bullseye.id_rsa /kernel/image/
COPY --from=syzkaller_builder /shellphish/syzkaller /shellphish/syzkaller

RUN mkdir -p /shellphish/syzkaller/benign_syzprogs_new
COPY syzconfig.cfg /shellphish/syzkaller/
COPY syzconfig-repro.cfg /shellphish/syzkaller/
COPY kernel.config /shellphish/syzkaller/
COPY run_repro.sh /shellphish/syzkaller/
COPY reproguy/repro.py /shellphish/repro.py

COPY syzkaller_crashes_upload.py /
COPY syzkaller_crashes_download.py /
COPY syzprog2c_auto.py /
COPY corpus.db /
COPY crashes.tar.gz /crashes.tar.gz

# Set entrypoint to check script
USER root
#ENTRYPOINT ["/bin/bash"]
