# checkov:skip=CKV_DOCKER_3:We create a user for the container & drop privileges at runtime to support runtime UID remapping

FROM python:3.12-slim

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# checkov:skip=CKV_DOCKER_9:rm -rf apt is causing this to fire erroneously
# we actually do want latest for these pip packages & do not care what version git is
# we want to use `cd` rather than WORKDIR here to do it in a single layer
# hadolint ignore=DL3013,DL3008,DL3003
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir --upgrade 'poetry>=1.8.3' && \
    apt-get update && \
    apt-get install --yes --no-install-recommends \
        ca-certificates \
        curl \
        git \
        gosu \
        make \
        rsync \
        ssh \
        && \
    install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc && \
    chmod a+r /etc/apt/keyrings/docker.asc && \
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
      $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
      tee /etc/apt/sources.list.d/docker.list > /dev/null && \
    apt-get update && \
    apt-get install --yes --no-install-recommends \
        docker-ce \
        docker-ce-cli \
        containerd.io \
        docker-buildx-plugin \
        docker-compose-plugin \
        && \
    apt-get clean autoclean && \
    apt-get autoremove --yes && \
    cd /var/lib && \
    rm -rf apt dpkg cache log


RUN curl -fsSL "https://github.com/mikefarah/yq/releases/download/v4.44.1/yq_linux_amd64" -o yq && \
    echo " 6dc2d0cd4e0caca5aeffd0d784a48263591080e4a0895abe69f3a76eb50d1ba3 yq" | sha256sum --check && \
    chmod a+x yq && \
    mv yq /usr/bin

RUN mkdir /var/log/capi && \
    chmod 755 /var/log/capi

# preinstall dependencies for faster iteration
COPY pyproject.toml poetry.lock /code/
WORKDIR /code
RUN poetry config virtualenvs.in-project true && \
    poetry install --no-root

COPY entrypoint.sh README.md /code/
COPY competition_api /code/competition_api/
RUN poetry install

# disables pyc files
ENV PYTHONDONTWRITEBYTECODE 1 # disables pyc files

# disables buffering stdout and stderr
ENV PYTHONUNBUFFERED 1

ENV AIXCC_PORT 8080

HEALTHCHECK --interval=5s --retries=30 --start-period=3s --timeout=5s \
    CMD curl --fail http://localhost:${AIXCC_PORT} || exit 1

ARG api_version=0.0.0
ENV AIXCC_API_VERSION=${api_version}

ENTRYPOINT ["/code/entrypoint.sh"]
