#!/usr/bin/env bash

exec docker run -it --rm -v /var/run/docker.sock:/var/run/docker.sock --privileged -w /root/pipelines -e PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/root/venv/bin --net aixcc-sc-crs-sandbox_default "$@" ghcr.io/shellphish-support-syndicate/aixcc-leader:latest bash
