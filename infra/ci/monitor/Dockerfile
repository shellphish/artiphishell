# aixcc-build: aixcc-monitor
ARG IMAGE_PREFIX=
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell
FROM ${IMAGE_PREFIX}aixcc-dependencies-base:latest

WORKDIR /opt/actions-runner
RUN curl -o /opt/actions-runner-linux-x64-2.322.0.tar.gz \
    -L https://github.com/actions/runner/releases/download/v2.322.0/actions-runner-linux-x64-2.322.0.tar.gz \
    && tar xzf /opt/actions-runner-linux-x64-2.322.0.tar.gz \
    && rm /opt/actions-runner-linux-x64-2.322.0.tar.gz

RUN apt-get update && apt-get install -y curl uuid-runtime

ADD run_worker.sh /opt/run_worker.sh

ENV RUNNER_ALLOW_RUNASROOT=1

CMD ["/opt/run_worker.sh"]
