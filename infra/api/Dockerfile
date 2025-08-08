# aixcc-build: aixcc-crs-api
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

ADD libs/pydatatask/ /app/libs/pydatatask
RUN pip install /app/libs/pydatatask

COPY --from=libs /libs/crs-utils /app/libs/crs-utils
RUN pip install -e /app/libs/crs-utils

COPY --from=libs /libs/crs-api /app/libs/crs-api
RUN pip install -e /app/libs/crs-api

ADD infra/ /app/infra

CMD ["/app/infra/api/run_api.sh"]
