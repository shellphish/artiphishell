# aixcc-build: aixcc-antlr4-parser
FROM python:3.10
LABEL org.opencontainers.image.source=https://github.com/aixcc-sc/asc-crs-shellphish
RUN pip install antlr4-tools antlr4-python3-runtime argparse tqdm GitPython jsonschema pyyaml numpy requests
RUN git config --global --add safe.directory '*'
WORKDIR /app
COPY . /app