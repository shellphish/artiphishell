# aixcc-build: aixcc-submitter
ARG IMAGE_PREFIX=
FROM ${IMAGE_PREFIX}aixcc-component-base

RUN pip install PyYAML argparse pysarif pandas tqdm jsonschema requests
WORKDIR /app
COPY ./submitter /app
LABEL org.opencontainers.image.source=https://github.com/aixcc-sc/asc-crs-shellphish
