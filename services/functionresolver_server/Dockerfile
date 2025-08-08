# aixcc-build: aixcc-functionresolver-server
ARG IMAGE_PREFIX=
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell
FROM ${IMAGE_PREFIX}aixcc-component-base:latest

WORKDIR /app

RUN mkdir -p /app/functionresolver_server_workdir


COPY . /app/functionresolver_server
RUN pip install -e /app/functionresolver_server

CMD ["python3", "-m", "functionresolver_server.src.server"]
