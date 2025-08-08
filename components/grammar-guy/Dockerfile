# aixcc-build: aixcc-grammar-guy
ARG IMAGE_PREFIX=
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell
FROM ${IMAGE_PREFIX}aixcc-component-base
LABEL org.opencontainers.image.source=${SOURCE_REPO}
ARG ISOLATED=
RUN test -z "${ISOLATED}" || echo "deb [trusted=yes arch=amd64] http://apt-mirror-$(grep DISTRIB_RELEASE= /etc/lsb-release | cut -d= -f2 | sed 's/\./-/g'):$(grep DISTRIB_RELEASE= /etc/lsb-release | cut -d= -f2 | sed 's/\.//g') $(grep DISTRIB_CODENAME /etc/lsb-release | cut -d= -f2) main universe" > /etc/apt/sources.list

RUN pip3 install tiktoken lxml commentjson

COPY . /shellphish/grammar_guy/

RUN cd /shellphish/grammar_guy/tools/ && ./build.sh
RUN cd /shellphish/grammar_guy/ && pip3 install -e .
RUN cd /shellphish/libs/nautilus/ && ./build.sh

RUN apt update && apt install -y unar