ARG BASE_IMAGE=
ARG PREBUILD_IMAGE=

# pull the prebuild image in with a given name
FROM ${PREBUILD_IMAGE} AS codeql-prebuild

FROM ${BASE_IMAGE} AS final-builder

ENV CODEQL_VERSION="2.22.0"
COPY --from=codeql-prebuild /shellphish/codeql /shellphish/codeql

ENV PATH="/shellphish/codeql:${PATH}"

COPY codeql_build.py /shellphish/codeql_build.py
RUN cp /usr/local/bin/compile /usr/local/bin/compile.old
COPY compile /usr/local/bin/compile
