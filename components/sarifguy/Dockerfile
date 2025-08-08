# aixcc-build: aixcc-sarifguy
ARG IMAGE_PREFIX=
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell

FROM ${IMAGE_PREFIX}aixcc-component-base
LABEL org.opencontainers.image.source=${SOURCE_REPO}

RUN pip install sarif-tools 

COPY ./src/ /src/

WORKDIR /src


