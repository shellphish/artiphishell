# aixcc-build: aixcc-dyva
ARG IMAGE_PREFIX=
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell
FROM ${IMAGE_PREFIX}aixcc-libs:latest AS libs
FROM ${IMAGE_PREFIX}aixcc-component-base

RUN apt-get update && apt-get install -y gdb gdbserver socat

RUN wget -O ~/.gdbinit-gef.py -q https://gef.blah.cat/py
RUN echo "source ~/.gdbinit-gef.py" >> ~/.gdbinit

# This is to simulate the /shared folder on the host
RUN mkdir -p /shared/dyva

WORKDIR /app

# Install debug-lib
COPY --from=libs /libs/debug-lib /shellphish/libs/debug-lib
RUN pip install --editable /shellphish/libs/debug-lib

ADD run_scripts /app/run_scripts
ADD ./dyva /app/dyva/