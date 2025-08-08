# aixcc-build: aixcc-povguy
ARG IMAGE_PREFIX=
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell

FROM ${IMAGE_PREFIX}aixcc-component-base
LABEL org.opencontainers.image.source=${SOURCE_REPO}

RUN mkdir -p /shellphish/
COPY . /shellphish/povguy
WORKDIR /shellphish/povguy
