# aixcc-build: aixcc-asanguy
ARG IMAGE_PREFIX=
FROM ${IMAGE_PREFIX}aixcc-dependencies-base
LABEL org.opencontainers.image.source=https://github.com/aixcc-sc/asc-crs-shellphish

RUN apt-get update && apt-get install -y python3 python3-pip wget clang-15 curl rsync jq
RUN wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -O /usr/bin/yq && chmod +x /usr/bin/yq

ENV ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer-15

COPY asan2report.py /asan2report.py
