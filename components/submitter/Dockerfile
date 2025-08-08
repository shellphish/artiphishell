# aixcc-build: aixcc-submitter
ARG IMAGE_PREFIX=
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell
FROM ${IMAGE_PREFIX}aixcc-libs:latest as libs
FROM ${IMAGE_PREFIX}aixcc-component-base:latest

# COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/
RUN pip install uv

WORKDIR /app

RUN uv venv --system-site-packages

ADD pyproject.toml pyproject.toml

COPY --from=libs /libs/crs-api /shellphish/libs/crs-api

# Install dependencies
RUN sed -i 's|../../libs/|/shellphish/libs/|' pyproject.toml
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --no-install-project

ADD src /app/src
ADD run_submitter.sh /app/run_submitter.sh
ADD run-submitter-from-backup.sh /app/run-submitter-from-backup.sh

ENV VIRTUAL_ENV=/app/.venv
