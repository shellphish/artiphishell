# aixcc-build: aixcc-discovery-guy

ARG IMAGE_PREFIX=
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell
FROM ${IMAGE_PREFIX}aixcc-libs:latest AS libs
FROM ${IMAGE_PREFIX}aixcc-component-base
LABEL org.opencontainers.image.source=${SOURCE_REPO}

RUN mkdir /resources

RUN pip install --upgrade pip
RUN pip install ipython ipdb rich pyyaml gitpython pycparser docker sarif-tools fuzzing whatthepatch networkx


# debugging env
ENV LOG_LLM=0
ENV LOG_LEVEL=WARNING

# agentlib env
# TODO: disable this when not debugging mode.
# this dumps the conversation in the volumes folder.
ENV AGENTLIB_SAVE_FILES=off

# This should be set to 1 if you want to use the LLM API
#ENV USE_LLM_API=1
ENV USE_LLM_API=1
ENV LITELLM_KEY=sk-PhMkn-ug9XmXSGLryqENvA

COPY --from=libs /libs/debug-lib /shellphish/libs/debug-lib
RUN pip install --editable /shellphish/libs/debug-lib

# Just create a new folder for shellphish stuff
COPY ./src /src/

WORKDIR /src
