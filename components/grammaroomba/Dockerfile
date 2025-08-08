# aixcc-build: aixcc-grammaroomba
ARG IMAGE_PREFIX=
FROM ${IMAGE_PREFIX}aixcc-component-base
LABEL org.opencontainers.image.source=${SOURCE_REPO}
ARG ISOLATED=
RUN test -z "${ISOLATED}" || echo "deb [trusted=yes arch=amd64] http://apt-mirror-$(grep DISTRIB_RELEASE= /etc/lsb-release | cut -d= -f2 | sed 's/\./-/g'):$(grep DISTRIB_RELEASE= /etc/lsb-release | cut -d= -f2 | sed 's/\.//g') $(grep DISTRIB_CODENAME /etc/lsb-release | cut -d= -f2) main universe" > /etc/apt/sources.list

RUN apt update && apt install -y unar
RUN python3 -m pip install --upgrade pip
RUN pip3 install -e /shellphish/libs/crs-utils
RUN pip3 install tiktoken lxml commentjson

COPY . /shellphish/grammaroomba/

RUN cd /shellphish/grammaroomba/ && pip3 install -e .
RUN cd /shellphish/libs/nautilus/ && ./build.sh