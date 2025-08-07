# aixcc-build: aixcc-dyva
ARG IMAGE_PREFIX=
FROM ${IMAGE_PREFIX}aixcc-component-base
LABEL org.opencontainers.image.source=https://github.com/aixcc-sc/asc-crs-shellphish

RUN apt-get update && apt-get install -y gdb gdbserver socat

COPY UniversalDBG /UniversalDBG
RUN pip3 install /UniversalDBG tree-sitter==0.21.3 tree-sitter-languages==1.10.2
RUN python3 -c 'import universal_dbg' #This just tests if the pip install worked
COPY ./modifications /modifications
COPY ./dyva_runner /dyva_runner
