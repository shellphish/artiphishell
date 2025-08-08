# aixcc-build: aixcc-ccache-server
ARG IMAGE_PREFIX=
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell
FROM ${IMAGE_PREFIX}aixcc-dependencies-base:latest

RUN apt-get update && apt-get install -y ccache && rm -rf /var/lib/apt/lists/*

VOLUME ["/ccache"]

ENV CCACHE_DIR=/ccache

RUN mkdir -p /ccache && chmod -R 777 /ccache

ENV PATH="/usr/lib/ccache:$PATH"

# This image does not "serve" anything. It acts as a way to run ccache commands 
# without polluting other images/containers. 

CMD ["ccache", "-M", "100G", "--set-config=log_file=/ccache/ccache.log", "--set-config=log_file=/ccache/ccache.debug"]
