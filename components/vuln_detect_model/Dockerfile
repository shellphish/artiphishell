# aixcc-build: aixcc-vuln-model
ARG IMAGE_PREFIX=
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell

FROM ${IMAGE_PREFIX}aixcc-dependencies-base
LABEL org.opencontainers.image.source=${SOURCE_REPO}

RUN mkdir -p /app/

RUN pip install aiolimiter pandas==2.1.4
COPY model_zoo /app/model_zoo
RUN pip install /app/model_zoo/

COPY . /app/
WORKDIR /app/


