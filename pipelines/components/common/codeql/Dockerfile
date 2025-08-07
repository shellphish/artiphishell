# aixcc-build: aixcc-codeql
ARG IMAGE_PREFIX=
FROM ${IMAGE_PREFIX}aixcc-dependencies-base
LABEL org.opencontainers.image.source=https://github.com/aixcc-sc/asc-crs-shellphish

RUN apt-get update && apt-get install -y clang-14 python-is-python3 python3-pip rsync wget curl git jq
RUN pip install yq

RUN mkdir -p /scripts/unix/ /shellphish
WORKDIR /scripts/unix/

COPY downloads/codeql-bundle-linux64.tar.gz /shellphish/
RUN wget "https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.15.5/codeql-bundle-linux64.tar.gz" -O- | tar -xz

ENV PATH="/scripts/unix/codeql:${PATH}"

# compiled qlpacks cache will be at /root/.codeql
RUN codeql query compile /scripts/unix/codeql/qlpacks/codeql/java-all -j0 --keep-going --common-caches=/work/.codeql || true
RUN codeql query compile /scripts/unix/codeql/qlpacks/codeql/cpp-all -j0 --keep-going --common-caches=/work/.codeql || true
RUN pip install jinja2
COPY qlpacks/ ./
COPY downloads/* /shellphish/
COPY guest_content/* /shellphish/
