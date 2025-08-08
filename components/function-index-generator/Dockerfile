# aixcc-build: aixcc-function-index-generator

ARG IMAGE_PREFIX=

FROM ${IMAGE_PREFIX}aixcc-component-base:latest
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell

LABEL org.opencontainers.image.source=${SOURCE_REPO}
WORKDIR /function-index-generator
COPY . /function-index-generator/
RUN pip install -e /shellphish/libs/crs-utils
