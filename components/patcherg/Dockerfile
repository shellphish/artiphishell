# aixcc-build: aixcc-patcherg
ARG IMAGE_PREFIX=
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell
# Create multi stage build so we can copy from libs
FROM ${IMAGE_PREFIX}aixcc-libs:latest AS libs
FROM ${IMAGE_PREFIX}aixcc-component-base
LABEL org.opencontainers.image.source=${SOURCE_REPO}

COPY --from=libs /libs/graphquery /shellphish/libs/graphquery
RUN pip3 install -e /shellphish/libs/graphquery

COPY patcherg /patcherg/patcherg
COPY pyproject.toml /patcherg/pyproject.toml
COPY scripts /patcherg/scripts

WORKDIR /patcherg
RUN pip install -e .