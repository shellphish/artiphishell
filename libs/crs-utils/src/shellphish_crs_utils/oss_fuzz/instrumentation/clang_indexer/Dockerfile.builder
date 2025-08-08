ARG BASE_IMAGE=
ARG PREBUILD_IMAGE=

FROM ${PREBUILD_IMAGE} AS prebuild
FROM ${BASE_IMAGE}

COPY --from=prebuild /shellphish/blobs/offline-packages /shellphish/blobs/offline-packages
RUN cd /shellphish/blobs/offline-packages && \
    apt install -y ./*.deb

RUN git config --global --add safe.directory '*'
RUN mkdir -p $SRC/shellphish

COPY clang-indexer $SRC/shellphish/clang-indexer
COPY --from=prebuild /shellphish/blobs/pypi-packages /shellphish/blobs/pypi-packages
RUN pip install --no-index --find-links=/shellphish/blobs/pypi-packages \
    joblib clang==18.1.8 && \
    pip install -e $SRC/shellphish/clang-indexer

# Bear
COPY --from=prebuild /shellphish/blobs/bear /usr/local/bin/bear
COPY --from=prebuild /shellphish/blobs/bear.tar.gz .
COPY bear_config.json /bear_config.json
RUN tar -xf bear.tar.gz -C /usr/local/lib/ && \
    chmod +x /usr/local/lib/bear/wrapper && \
    chmod +x /usr/local/bin/bear

RUN mv /usr/local/bin/compile /usr/local/bin/compile.old
COPY compile /usr/local/bin/compile
