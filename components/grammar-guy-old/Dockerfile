# aixcc-build: aixcc-grammar-guy-old
ARG IMAGE_PREFIX=
FROM ${IMAGE_PREFIX}aixcc-component-base
LABEL org.opencontainers.image.source=https://github.com/aixcc-sc/asc-crs-shellphish
ARG ISOLATED=
RUN test -z "${ISOLATED}" || echo "deb [trusted=yes arch=amd64] http://apt-mirror-$(grep DISTRIB_RELEASE= /etc/lsb-release | cut -d= -f2 | sed 's/\./-/g'):$(grep DISTRIB_RELEASE= /etc/lsb-release | cut -d= -f2 | sed 's/\.//g') $(grep DISTRIB_CODENAME /etc/lsb-release | cut -d= -f2) main universe" > /etc/apt/sources.list

RUN pip3 install tiktoken

COPY . /shellphish/grammar_guy/

RUN cd /shellphish/grammar_guy/tools/ && ./build.sh
RUN cd /shellphish/grammar_guy/ && pip3 install -e .
RUN pip3 install -e /shellphish/grammar_guy/tools/grammarinator