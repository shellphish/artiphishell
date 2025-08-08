
ARG IMAGE_PREFIX=
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell
FROM ${IMAGE_PREFIX}aixcc-component-base
LABEL org.opencontainers.image.source=${SOURCE_REPO}

# =============================================
# Generic packages toolchain/utilities/folders
# =============================================
#RUN apt -y install vim wget gcc g++ git make file rsync python3 python3-pip curl flex bison
RUN mkdir /resources

RUN pip install --upgrade pip
RUN pip install ipython ipdb rich pyyaml

# =============================================
# Install docker buildx plugin
# =============================================
RUN mkdir -p $HOME/.docker/cli-plugins
RUN wget -qO $HOME/.docker/cli-plugins/docker-buildx https://github.com/docker/buildx/releases/download/v0.15.0-rc2/buildx-v0.15.0-rc2.linux-amd64
RUN chmod +x $HOME/.docker/cli-plugins/docker-buildx

# ================================================
# Commands to provision the kernel-guy environment
# ================================================
# RUN apt -y install qemu-system
# RUN mkdir /resources/kernel_guy
# RUN mkdir /resources/kernel_guy/linux-kernel-source
# RUN mkdir /resources/kernel_guy/debootstrap
# COPY ./resources/kernel_guy/debootstrap/bookworm.img /resources/kernel_guy/debootstrap/bookworm.img
# COPY ./resources/kernel_guy/debootstrap/bookworm.id_ecdsa /resources/kernel_guy/debootstrap/bookworm.id_ecdsa
# COPY ./resources/kernel_guy/debootstrap/bookworm.id_ecdsa.pub /resources/kernel_guy/debootstrap/bookworm.id_ecdsa.pub

# ================================================
# Commands to provision the c-guy environment
# ================================================
#RUN mkdir /resources/c_guy

# ================================================
# Commands to provision the java-guy environment
# ================================================
#RUN mkdir /resources/java_generic_guy

# ================================================
# 🐛 DEBUGGING STUFF, WIPE LATER
# ================================================
# This is to simulate the folder pydatatask is giving me

# This is to simulate the /shared folder on the host
RUN mkdir -p /shared/invguy

# Just create a new folder for shellphish stuff
COPY ./src/ /src/

RUN wget -q -O /resources/linux-6.11.tar.gz https://github.com/torvalds/linux/archive/refs/tags/v6.11.tar.gz

