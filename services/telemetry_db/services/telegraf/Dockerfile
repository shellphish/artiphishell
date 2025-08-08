FROM telegraf:1.32-alpine

ARG IMAGE_PREFIX

COPY ./telegraf.conf /etc/telegraf/telegraf.conf

RUN if [ -n "$IMAGE_PREFIX" ]; then \
    sed -i 's|unix:///var/run/docker.sock|tcp://docker-builder:2375|g' /etc/telegraf/telegraf.conf; \
fi