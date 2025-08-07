# aixcc-build: aixcc-coverageguy

# this image comes with crs-utils
# to build aixcc-component-base locally cd to shellphish-crs/pipelines/local_run and run rebuild_local.sh

ARG IMAGE_PREFIX=

####################################################################################################
####################################################################################################
FROM ${IMAGE_PREFIX}aixcc-component-base as coverageguy-base
LABEL org.opencontainers.image.source=https://github.com/aixcc-sc/asc-crs-shellphish

# # =============================================
# # Generic packages toolchain/utilities/folders
# # =============================================
# RUN apt-get update &&  \
#     apt-get upgrade -y && \
#     apt-get install -y \
#     make \
#     autoconf \
#     libtool \
#     wget \
#     build-essential \
#     python3-dev \
#     python3-setuptools \
#     automake \
#     cmake \
#     git \
#     flex \
#     bison \
#     libglib2.0-dev \
#     libpixman-1-dev \
#     cargo \
#     libgtk-3-dev \
#     python-is-python3 \
#     python3-pip \
#     rsync \
#     jq \
#     apt-transport-https \
#     ca-certificates \
#     curl \
#     software-properties-common \
#     clang-14 clang \
#     patchelf \
#     strace \
#     ltrace \
#     htop \
#     procps \
#     inotify-tools \
#     lsb-release

RUN pip3 install lxml
RUN mkdir /src
COPY ./c_monitor.sh /src/c_monitor.sh
COPY ./java_monitor.sh /src/java_monitor.sh
COPY ./find_similar_seeds.py /src/find_similar_seeds.py
COPY ./resources/ /shellphish/coverageguy/

# 🛡️ Just to make sure
RUN chmod +x /src/c_monitor.sh
RUN chmod +x /src/java_monitor.sh
RUN chmod +x /shellphish/coverageguy/build_target.sh
RUN chmod +x /shellphish/coverageguy/build_docker_image.sh
RUN chmod +x /shellphish/coverageguy/inotify_sync.sh