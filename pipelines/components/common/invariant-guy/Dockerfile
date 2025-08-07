# aixcc-build: aixcc-invariantguy

ARG IMAGE_PREFIX=
FROM ${IMAGE_PREFIX}aixcc-component-base
LABEL org.opencontainers.image.source=https://github.com/aixcc-sc/asc-crs-shellphish

# =============================================
# Generic packages toolchain/utilities/folders
# =============================================
RUN apt -y update && apt -y upgrade
#RUN apt -y install vim wget gcc g++ git make file rsync python3 python3-pip curl flex bison
RUN mkdir /resources

RUN pip install --upgrade pip
RUN pip install ipython ipdb rich pyyaml

# =============================================
# Install docker buildx plugin
# =============================================
RUN mkdir -p $HOME/.docker/cli-plugins
RUN wget -O $HOME/.docker/cli-plugins/docker-buildx https://github.com/docker/buildx/releases/download/v0.15.0-rc2/buildx-v0.15.0-rc2.linux-amd64
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
RUN mkdir /out-world

# This is to simulate the /shared folder on the host
RUN mkdir -p /shared/invguy

# Just create a new folder for shellphish stuff
COPY ./src/ /src/
