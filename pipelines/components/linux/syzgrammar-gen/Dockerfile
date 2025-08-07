# aixcc-build: aixcc-syzgrammar-gen

ARG IMAGE_PREFIX=

FROM ${IMAGE_PREFIX}aixcc-component-base
LABEL org.opencontainers.image.source=https://github.com/aixcc-sc/asc-crs-shellphish

# Clone and build syzkaller
COPY ./syzlangrs /shellphish/syzlangrs
WORKDIR /shellphish/syzlangrs
RUN ./build.sh

ENV OPENAI_API_KEY=sk-proj-BwxEmfBAeehF36oYDBGMT3BlbkFJIq8WjxCwsaMDU32Wmsvm
ENV ANTHROPIC_API_KEY=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

ENV LITELLM_KEY='sk-artiphishell'
ENV AIXCC_LITELLM_HOSTNAME='http://beatty.unfiltered.seclab.cs.ucsb.edu:4000'

WORKDIR /shellphish/joern
COPY ./joern/joern-cli.zip ./joern-cli.zip
RUN unzip ./joern-cli.zip

COPY . /shellphish/syzgrammar-gen
WORKDIR /shellphish/syzgrammar-gen
RUN pip install -e .

WORKDIR /shellphish/work
