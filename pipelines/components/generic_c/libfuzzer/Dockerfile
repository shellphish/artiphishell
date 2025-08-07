# aixcc-build: aixcc-libfuzzer

ARG IMAGE_PREFIX=
FROM ${IMAGE_PREFIX}aixcc-dependencies-base
LABEL org.opencontainers.image.source=https://github.com/aixcc-sc/asc-crs-shellphish

RUN apt install -y openssl libssl-dev

RUN mkdir -p /shellphish/libfuzzer/
COPY ./libfuzzer_modifications/* /shellphish/libfuzzer/
COPY ./crashmon.py /shellphish/libfuzzer/
