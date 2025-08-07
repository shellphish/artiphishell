#syntax=docker/dockerfile:1.4
#aixcc-build:aixcc-quickseed 

ARG IMAGE_PREFIX=
FROM ${IMAGE_PREFIX}aixcc-component-base
LABEL org.opencontainers.image.source=https://github.com/aixcc-sc/asc-crs-shellphish

RUN apt-get update && apt-get install -y python3 python3-pip
RUN apt-get install -y git vim curl wget
ENV AGENTLIB_SAVE_FILES=0
WORKDIR /QuickSeed
COPY QuickSeed QuickSeed
COPY requirements.txt requirements.txt
COPY setup.cfg setup.cfg
COPY setup.py setup.py

RUN pip install -e .


COPY test_main.sh /test_main.sh
RUN chmod +x /test_main.sh


# ENV LITELLM_KEY='sk-artiphishell'
# ENV AIXCC_LITELLM_HOSTNAME='http://beatty.unfiltered.seclab.cs.ucsb.edu:4000'
# ENV RETRIEVAL_API='http://beatty.unfiltered.seclab.cs.ucsb.edu:48751'
# ENV EMBEDDING_API='http://beatty.unfiltered.seclab.cs.ucsb.edu:49152'

#ENV SRC="/tmp/src"
#ENV CRASHES="/tmp/crashes"
#ENV OUT="/tmp/out"
#RUN mkdir -p ${SRC} ${CRASHES} ${OUT}
