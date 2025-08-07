# aixcc-build: aixcc-find-first-crash-commit
ARG IMAGE_PREFIX=
FROM ${IMAGE_PREFIX}aixcc-component-base
LABEL org.opencontainers.image.source=https://github.com/aixcc-sc/asc-crs-shellphish

RUN apt-get update && apt-get install -y python-is-python3 python3-pip rsync wget curl git jq
RUN wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -O /usr/bin/yq && chmod +x /usr/bin/yq

COPY ./find_first_crash_commit.py /find_first_crash_commit.py
COPY ./requirements.txt /requirements.txt
RUN pip3 install -r /requirements.txt
