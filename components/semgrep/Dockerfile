# aixcc-build: aixcc-semgrep
ARG IMAGE_PREFIX=
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell

FROM ${IMAGE_PREFIX}aixcc-component-base
LABEL org.opencontainers.image.source=${SOURCE_REPO}

RUN pip install semgrep

COPY rules /shellphish_semgrep_rules
COPY semgrep.py /semgrep.py