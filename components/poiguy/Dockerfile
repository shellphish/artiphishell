# aixcc-build: aixcc-poi-guy

ARG IMAGE_PREFIX=
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell

FROM ${IMAGE_PREFIX}aixcc-component-base:latest

LABEL org.opencontainers.image.source=${SOURCE_REPO}
# RUN pip install PyYAML argparse pysarif pandas antlr4-tools antlr4-python3-runtime tqdm jsonschema
# RUN apt-get update -y && apt-get install rsync -y
WORKDIR /poiguy
COPY . /poiguy
RUN pip install -e /shellphish/libs/crs-utils