# aixcc-build: aixcc-shellphish-jazzer
ARG IMAGE_PREFIX=
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell
FROM ${IMAGE_PREFIX}aixcc-component-base
LABEL org.opencontainers.image.source=${SOURCE_REPO}

RUN mkdir -p /shellphish/jazzer
COPY output_to_pdt.sh /shellphish/jazzer/output_to_pdt.sh
COPY cross_node_sync_seeds.sh /shellphish/jazzer/cross_node_sync_seeds.sh

RUN ls -al /usr/local/bin
RUN /usr/local/bin/yq --version
