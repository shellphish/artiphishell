# aixcc-build: aixcc-pdt-agent
ARG IMAGE_PREFIX=
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell
FROM ${IMAGE_PREFIX}aixcc-libs:latest as libs
FROM ${IMAGE_PREFIX}aixcc-dependencies-base:latest

WORKDIR /app

# Make a virtual environment and install the dependencies
RUN python -m venv /app/venv
ENV PATH /app/venv/bin:$PATH

COPY /libs/crs-telemetry /app/libs/crs-telemetry
RUN pip install -e /app/libs/crs-telemetry

ADD libs/pydatatask/pyproject.toml /app/libs/pydatatask/pyproject.toml
RUN mkdir -p /app/libs/pydatatask/pydatatask \
    && echo "__version__='0'" > /app/libs/pydatatask/pydatatask/__init__.py \
    && pip install /app/libs/pydatatask

ADD libs/crs-utils/pyproject.toml /app/libs/crs-utils/pyproject.toml
RUN pip install /app/libs/crs-utils && pip install gunicorn yappi

RUN apt-get update -y && apt-get install graphviz-dev -y && pip install pygraphviz && curl -sL https://aka.ms/InstallAzureCLIDeb | bash

# Install nginx for large file uploads service
RUN apt-get update -y && \
    apt-get install -y nginx && \
    rm -f /etc/nginx/sites-enabled/default && \
    mkdir -p /tmp/pdt-uploads

# Add nginx configuration for PDT uploads
COPY infra/agent/nginx_pdt_upload.conf /etc/nginx/conf.d/pdt_upload.conf

ADD libs/pydatatask/ /app/libs/pydatatask
RUN pip install /app/libs/pydatatask

COPY --from=libs /libs/crs-utils /app/libs/crs-utils
RUN pip install -e /app/libs/crs-utils

COPY --from=libs /libs/analysis-graph/ /app/libs/analysis-graph
RUN pip install -e /app/libs/analysis-graph

RUN pip install -e /app/libs/pydatatask

ADD libs/ /app/libs
ADD local_run/ /app/local_run

# Add all pipeline yaml files
ADD infra/ /app/infra
ADD pipeline.yaml /app/pipeline.yaml
ADD pipelines/ /app/pipelines
ADD components/ /app/components

RUN head -c 10 /dev/urandom | xxd -ps > /app/.pipeline-id

CMD ["/app/infra/agent/run_agent.sh"]
