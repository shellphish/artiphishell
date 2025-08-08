#aixcc-build:aixcc-quickseed
ARG IMAGE_PREFIX=
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell
FROM ${IMAGE_PREFIX}aixcc-component-base
LABEL org.opencontainers.image.source=${SOURCE_REPO}

ENV AGENTLIB_SAVE_FILES=0
WORKDIR /quickseed
COPY QuickSeed QuickSeed
COPY tests tests
COPY requirements.txt requirements.txt
COPY setup.cfg setup.cfg
COPY setup.py setup.py
COPY scripts/run_quickseed.sh scripts/run_quickseed.sh
RUN chmod +x scripts/run_quickseed.sh


COPY scripts/prepare_quickseed.sh scripts/prepare_quickseed.sh
COPY scripts/prepare_quickseed.py scripts/prepare_quickseed.py
RUN chmod +x scripts/prepare_quickseed.sh

RUN pip install -e .
RUN pip install -e /shellphish/libs/graphquery/

COPY test_main.sh /test_main.sh
RUN chmod +x /test_main.sh

COPY scripts/aggregate_build_config.py scripts/aggregate_build_config.py

ENV USE_LLM_API=1
ENV LOG_LEVEL=info
ENV LOG_LLM=1

# ENV RETRIEVAL_API='http://beatty.unfiltered.seclab.cs.ucsb.edu:48751'
# ENV EMBEDDING_API='http://beatty.unfiltered.seclab.cs.ucsb.edu:49152'

ENV SRC="/tmp/src"
ENV CRASHES="/tmp/crashes"
ENV OUT="/tmp/out"

RUN mkdir -p ${SRC} ${CRASHES} ${OUT}
