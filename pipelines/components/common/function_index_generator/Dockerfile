# aixcc-build: aixcc-function-index-generator
FROM python:3.10
LABEL org.opencontainers.image.source=https://github.com/aixcc-sc/asc-crs-shellphish
RUN pip install PyYAML argparse pysarif pandas antlr4-tools antlr4-python3-runtime tqdm dask[complete]
RUN apt-get update -y && apt-get install rsync -y
WORKDIR /app
COPY . /app
