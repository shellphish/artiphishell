# aixcc-build: aixcc-clang-instrumentation
ARG IMAGE_PREFIX=
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell
#FROM ${IMAGE_PREFIX}aixcc-libs:latest AS libs
FROM ${IMAGE_PREFIX}aixcc-component-base
LABEL org.opencontainers.image.source=${SOURCE_REPO}

RUN mkdir -p /shellphish/blobs
RUN wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && ./llvm.sh 18 && rm llvm.sh 

RUN apt-get update &&  apt-get install -y \
git \
cmake \
ninja-build \
build-essential \
python3 \
libncurses5-dev \
python3-pip \
libzstd-dev \
libedit-dev \
libcurl4-gnutls-dev \
libncurses5-dev \
libz-dev \
libxml2-dev \
python3-dev \
automake \
flex \
bison \
libglib2.0-dev \
libpixman-1-dev \
python3-setuptools \
cargo \
libgtk-3-dev \
libncurses5 \
rsync \
wget \
curl \
libpcre3-dev 

RUN mkdir -p /shellphish/clang_instrumentation
RUN mkdir -p /shellphish/workdir

COPY src /shellphish/clang_instrumentation/src

RUN cd /shellphish/clang_instrumentation/src/passes && ./build.sh
RUN cd /shellphish/clang_instrumentation/src/runtime && make

# debugging env
ENV LOG_LLM=0
ENV LOG_LEVEL=WARNING

# agentlib env
# TODO: disable this when not debugging mode.
# this dumps the conversation in the volumes folder.
ENV AGENTLIB_SAVE_FILES=on

# This should be set to 1 if you want to use the LLM API
#ENV USE_LLM_API=1
ENV USE_LLM_API=1