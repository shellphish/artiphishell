ARG IMAGE_PREFIX=
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell
FROM ${IMAGE_PREFIX}aixcc-component-base:latest
LABEL org.opencontainers.image.source=${SOURCE_REPO}

RUN apt-get update && apt-get install -y python3 python3-pip wget clang-15 curl rsync jq
RUN wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -O /usr/bin/yq && chmod +x /usr/bin/yq

ENV ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer-15

WORKDIR /asan2report
COPY asan2report.py /asan2report/asan2report.py
