# aixcc-build: aixcc-cluster-fuzz

# Start from a base image
ARG IMAGE_PREFIX=
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell

FROM ${IMAGE_PREFIX}aixcc-component-base
LABEL org.opencontainers.image.source=${SOURCE_REPO}

WORKDIR /shellphish

ENV DEBIAN_FRONTEND=noninteractive

ADD oss-fuzz /oss-fuzz

CMD [ "/bin/bash" ]
