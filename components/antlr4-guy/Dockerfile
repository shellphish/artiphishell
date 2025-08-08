# aixcc-build: aixcc-antlr4-parser

ARG IMAGE_PREFIX=
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell

FROM ${IMAGE_PREFIX}aixcc-component-base

LABEL org.opencontainers.image.source=${SOURCE_REPO}
RUN pip install antlr4-tools antlr4-python3-runtime argparse tqdm GitPython jsonschema pyyaml numpy requests rich
RUN pip install -e /shellphish/libs/crs-utils
RUN git config --global --add safe.directory '*'
WORKDIR /shellphish/antlr4
COPY . /shellphish/antlr4