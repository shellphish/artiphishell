# aixcc-build: aixcc-competition-server-infra
ARG IMAGE_PREFIX=
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell
FROM ${IMAGE_PREFIX}aixcc-component-base:latest
ARG GITHUB_TOKEN=


ADD . /infra

WORKDIR /infra

RUN echo $GITHUB_TOKEN > /root/.git-credentials
ENTRYPOINT ["/infra/entrypoint.sh"]
