# aixcc-build: aixcc-patcherq
ARG IMAGE_PREFIX=
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell
FROM ${IMAGE_PREFIX}aixcc-libs:latest AS libs
FROM ${IMAGE_PREFIX}aixcc-component-base
LABEL org.opencontainers.image.source=${SOURCE_REPO}

RUN mkdir /resources

RUN apt-get install silversearcher-ag
RUN pip install --upgrade pip
RUN pip install ipython ipdb rich pyyaml xmltodict Levenshtein Faker whatthepatch

# Copy library from the libs dir
COPY --from=libs /libs/lspclient /shellphish/libs/lspclient
# Install lspclient
RUN pip3 install --ignore-installed -e /shellphish/libs/lspclient

RUN mkdir -p /shared/patcherq
RUN mkdir -p /shared/patcherq/stats

WORKDIR /shared/patcherq

# This is for the linter 
RUN apt-get install -y libncurses5

# debugging env
ENV LOG_LLM=0
ENV LOG_LEVEL=WARNING

# agentlib env
# TODO: disable this when not debugging mode.
# this dumps the conversation in the volumes folder.
ENV AGENTLIB_SAVE_FILES=on

# This should be set to 1 if you want to use the LLM API
#ENV USE_LLM_API=1
ENV USE_LLM_API=1

# Just create a new folder for shellphish stuff
COPY ./src/ /src/

WORKDIR /src
