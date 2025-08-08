# aixcc-build: aixcc-coverageguy

# this image comes with crs-utils
# to build aixcc-component-base locally cd to shellphish-crs/pipelines/local_run and run rebuild_local.sh

ARG IMAGE_PREFIX=
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell

####################################################################################################
####################################################################################################
FROM ${IMAGE_PREFIX}aixcc-component-base as coverageguy-base
LABEL org.opencontainers.image.source=${SOURCE_REPO}

RUN pip install pympler

RUN mkdir -p /shellphish/coverageguy
COPY . /shellphish/coverageguy/

RUN chmod +x /shellphish/coverageguy/run.sh