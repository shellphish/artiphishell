# aixcc-build: aixcc-shellphish-libfuzzer
ARG IMAGE_PREFIX=
FROM ${IMAGE_PREFIX}aixcc-libs:latest
FROM ${IMAGE_PREFIX}aixcc-component-base
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell
LABEL org.opencontainers.image.source=${SOURCE_REPO}

RUN mkdir -p /shellphish/libfuzzer
COPY output_to_pdt.sh /shellphish/libfuzzer/output_to_pdt.sh
COPY cross_node_sync_seeds.sh /shellphish/libfuzzer/cross_node_sync_seeds.sh

RUN ls -al /usr/local/bin
RUN /usr/local/bin/yq --version
WORKDIR /shellphish/libfuzzer
COPY . .
