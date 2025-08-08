# aixcc-build: aixcc-codeql
ARG IMAGE_PREFIX=ghcr.io/shellphish-support-syndicate/
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell
FROM ${IMAGE_PREFIX}aixcc-component-base
LABEL org.opencontainers.image.source=${SOURCE_REPO}

RUN mkdir -p /shellphish/codeql_installation
ARG CODEQL_VERSION="2.22.0"
RUN wget -qO- "https://github.com/github/codeql-action/releases/download/codeql-bundle-v${CODEQL_VERSION}/codeql-bundle-linux64.tar.gz" | tar -zxvf - -C /shellphish/codeql_installation
ENV PATH=/shellphish/codeql_installation/codeql:$PATH

# This is from shellphish-support-syndicate/codeql-mirror, run pack.sh in the repo to generate the latest pack
# This arg does nothing but force layer cache to be invalidated
ARG CODEQL_QUERIES_CACHE_TIMESTAMP=1750745085
RUN mkdir /shellphish/codeql_compiled_packs && \
    cd /shellphish/codeql_compiled_packs && \
    mkdir java-queries && \
    wget -qO- https://raw.githubusercontent.com/a3c1dd56-ce26-4695-aa35-01bc566eb8d4/70261b66-88f0-4957-9568-2dba2faf0916/refs/heads/main/java-queries.tgz | tar zxf - -C java-queries && \
    mkdir java-all && \
    wget -qO- https://raw.githubusercontent.com/a3c1dd56-ce26-4695-aa35-01bc566eb8d4/70261b66-88f0-4957-9568-2dba2faf0916/refs/heads/main/java-all.tgz | tar zxf - -C java-all && \
    mkdir cpp-queries && \
    wget -qO- https://raw.githubusercontent.com/a3c1dd56-ce26-4695-aa35-01bc566eb8d4/70261b66-88f0-4957-9568-2dba2faf0916/refs/heads/main/cpp-queries.tgz | tar zxf - -C cpp-queries && \
    mkdir cpp-all && \
    wget -qO- https://raw.githubusercontent.com/a3c1dd56-ce26-4695-aa35-01bc566eb8d4/70261b66-88f0-4957-9568-2dba2faf0916/refs/heads/main/cpp-all.tgz | tar zxf - -C cpp-all

COPY ./ /shellphish/codeql
