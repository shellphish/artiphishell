# aixcc-build: aixcc-kumu-shi-runner
ARG IMAGE_PREFIX=
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell
# Create multi stage build so we can copy from libs
FROM ${IMAGE_PREFIX}aixcc-libs:latest AS libs
FROM ${IMAGE_PREFIX}aixcc-component-base
LABEL org.opencontainers.image.source=${SOURCE_REPO}

COPY --from=libs /libs/kumu-shi /shellphish/libs/kumu-shi
RUN pip3 install -e /shellphish/libs/kumu-shi
COPY --from=libs /libs/testguy /shellphish/libs/testguy
RUN pip3 install -e /shellphish/libs/testguy
COPY run_kumushi.sh /kumushi/run_kumushi.sh
COPY run_kumushi_from_backup.sh /kumushi/run_kumushi_from_backup.sh

WORKDIR /kumushi

# debugging env
ENV LOG_LLM=1
ENV LOG_LEVEL=DEBUG
ENV PYTHONBREAKPOINT=ipdb.set_trace
ENV USE_LLM_API=1