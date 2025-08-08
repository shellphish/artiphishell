# aixcc-build: aixcc-lang-server
ARG IMAGE_PREFIX=
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell
FROM ${IMAGE_PREFIX}aixcc-dependencies-base:latest

#FROM ubuntu:22.04

# Update and install common dependencies
RUN apt-get update && \
    apt-get install -y \
        software-properties-common \
        wget \
        curl \
        gnupg2 \
        lsb-release \
        ca-certificates \
        netcat-traditional \
        file \
        unzip \
        iproute2 \
        socat \
        sudo \
        cmake \
        clang \
        openjdk-21-jdk && \
    apt-get clean

# Set JAVA_HOME
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64

# Add Python repository and install Python 3.10
RUN add-apt-repository ppa:deadsnakes/ppa && \
    apt-get update && \
    apt-get install -y python3.10 python3.10-venv python3.10-dev python3.10-distutils

# Set Python 3.10 as default
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.10 1

# Create and configure virtual environment
RUN python3 -m venv /venv && \
    /venv/bin/pip install --upgrade pip && \
    /venv/bin/pip install flask

# Set working directory
WORKDIR /app

# Copy application files
COPY . /app/

# Download and install clangd
RUN wget -q https://github.com/clangd/clangd/releases/download/19.1.2/clangd-linux-19.1.2.zip && \
    unzip clangd-linux-19.1.2.zip && \
    rm clangd-linux-19.1.2.zip && \
    mv clangd_19.1.2 /app/c-cpp/

# Debugging: Print versions (optional, can be removed later)
RUN python3 --version && java -version

# Set entrypoint
ENTRYPOINT ["/venv/bin/python", "server.py"]
