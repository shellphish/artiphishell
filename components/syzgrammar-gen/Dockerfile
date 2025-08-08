
ARG IMAGE_PREFIX=
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell

# TODO XXX This is a tmp hack to get the libraries into the image until we have are rebuilding the base image
# FROM ${IMAGE_PREFIX}aixcc-libs as libs

FROM ${IMAGE_PREFIX}aixcc-component-base
LABEL org.opencontainers.image.source=${SOURCE_REPO}

WORKDIR /shellphish/libs/syzlangrs
RUN ./build.sh

#ENV OPENAI_API_KEY=
#ENV ANTHROPIC_API_KEY=

ENV USE_LLM_API=1

WORKDIR /shellphish/joern
RUN curl -L -o ./joern-cli.zip https://github.com/joernio/joern/releases/download/v2.0.447/joern-cli.zip
#COPY ./joern/joern-cli.zip ./joern-cli.zip
RUN unzip ./joern-cli.zip

COPY . /shellphish/syzgrammar-gen
WORKDIR /shellphish/syzgrammar-gen
RUN pip install -e .

WORKDIR /shellphish/work
