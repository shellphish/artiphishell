# aixcc-build: aixcc-pov-patrol
ARG IMAGE_PREFIX=
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell

FROM ${IMAGE_PREFIX}aixcc-component-base
LABEL org.opencontainers.image.source=${SOURCE_REPO}

RUN pip install alive-progress

WORKDIR /pov-patrol
COPY ./pov_patch_check.py .