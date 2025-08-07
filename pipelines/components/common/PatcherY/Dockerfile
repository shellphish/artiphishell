# aixcc-build: aixcc-patchery
ARG IMAGE_PREFIX=
FROM ${IMAGE_PREFIX}aixcc-component-base
LABEL org.opencontainers.image.source=https://github.com/aixcc-sc/asc-crs-shellphish

COPY patchery /patchery/patchery
COPY setup.cfg /patchery/setup.cfg
COPY setup.py /patchery/setup.py
#COPY tests /patchery/tests
COPY Dockerfile.extensions /patchery/Dockerfile.extensions

WORKDIR /patchery
RUN pip install -e .[test]

RUN git config --global user.email "example@example.com" && git config --global user.name "jane doe"
ENV OPENAI_API_KEY="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"
ENV GOOGLE_API_KEY="AIzaSyDOeG3LqRyhLm5NG0B5FtOUPb3K6sZKT4g"
ENV ANTHROPIC_API_KEY="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"

# ENV LITELLM_KEY='sk-artiphishell'
# ENV AIXCC_LITELLM_HOSTNAME='http://beatty.unfiltered.seclab.cs.ucsb.edu:4000'
# ENV RETRIEVAL_API 
# ENV EMBEDDING_API
# ENV MODEL="oai-gpt-4o"
# RUN cd tests && python test_aicc.py
ENV SRC="/tmp/src"
ENV CRASHES="/tmp/crashes"
ENV OUT="/tmp/out"
RUN mkdir -p ${SRC} ${CRASHES} ${OUT}
