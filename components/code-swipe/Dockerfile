# aixcc-build: aixcc-code-swipe
ARG IMAGE_PREFIX=
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell

FROM ${IMAGE_PREFIX}aixcc-component-base
LABEL org.opencontainers.image.source=${SOURCE_REPO}

RUN mkdir -p /shellphish/
COPY . /shellphish/code-swipe/
WORKDIR /shellphish/code-swipe
