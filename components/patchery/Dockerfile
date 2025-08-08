# aixcc-build: aixcc-patchery
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

COPY patchery /patchery/patchery
COPY pyproject.toml /patchery/pyproject.toml
COPY Dockerfile.extensions /patchery/Dockerfile.extensions
COPY scripts /patchery/scripts

WORKDIR /patchery
RUN pip install -e .[test]
RUN pip install -e /shellphish/libs/aijon-lib

RUN git config --global user.email "example@example.com" && git config --global user.name "jane doe"
# debugging env
ENV LOG_LLM=0
ENV LOG_LEVEL=DEBUG
ENV PYTHONBREAKPOINT=ipdb.set_trace
# agentlib env
ENV AGENTLIB_SAVE_FILES=off

ENV SRC="/tmp/src"
ENV CRASHES="/tmp/crashes"
ENV OUT="/tmp/out"
RUN mkdir -p ${SRC} ${CRASHES} ${OUT}
