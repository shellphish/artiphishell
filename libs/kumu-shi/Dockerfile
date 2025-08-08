ARG IMAGE_PREFIX=
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell
FROM ${IMAGE_PREFIX}aixcc-component-base
LABEL org.opencontainers.image.source=${SOURCE_REPO}

COPY kumushi /kumushi/kumushi
COPY pyproject.toml /kumushi/pyproject.toml

WORKDIR /kumushi
RUN pip install -e .

# debugging env
ENV LOG_LLM=1
ENV LOG_LEVEL=DEBUG
ENV PYTHONBREAKPOINT=ipdb.set_trace