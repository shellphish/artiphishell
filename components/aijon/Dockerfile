# aixcc-build: aixcc-aijon

ARG IMAGE_PREFIX=
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell
FROM ${IMAGE_PREFIX}aixcc-libs:latest AS libs
FROM ${IMAGE_PREFIX}aixcc-component-base
LABEL org.opencontainers.image.source=${SOURCE_REPO}


RUN pip install --upgrade pip
RUN pip install ipython ipdb rich pyyaml unidiff loguru

COPY --from=libs /libs/aijon-lib /shellphish/libs/aijon-lib
RUN pip install --editable /shellphish/libs/aijon-lib

WORKDIR /aijon

COPY . /aijon/
