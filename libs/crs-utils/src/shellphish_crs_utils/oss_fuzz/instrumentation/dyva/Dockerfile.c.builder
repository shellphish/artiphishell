# Base image should always be the OSS FUZZ base image
ARG BASE_IMAGE=""
FROM ${BASE_IMAGE} 

RUN mkdir -p /shellphish/
COPY wrapper.sh /shellphish/
COPY patch_tools.sh /shellphish/

RUN chmod +x /shellphish/*.sh

RUN /shellphish/patch_tools.sh