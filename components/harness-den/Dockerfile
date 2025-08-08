# This Dockerfile will build an image that will provide an environment
# for the building, running, and testing of challenge project source.
#
# The base docker image is pre-built during the competition to
# support the pseudo-offline competition environment, as well
# as reducing time spent on dependency installations.
#
# Because of this, this Dockerfile will not be buildable at time
# of competition. It is simply for informational purposes.
#
# The location of the built base docker image can be found in the CP's
# project.yaml, as well as the .env.project file.
#
# Competitors are free to create their own docker images for use
# at their own discretion. No guarantees are made for custom images.
#
# To use a custom docker image with the run.sh script, modify
# then set the DOCKER_IMAGE_NAME environment variable:
#
#       DOCKER_IMAGE_NAME=my-custom-image ./run.sh

#################################################################################################################
FROM ghcr.io/shellphish-support-syndicate/jazzer:v3.0.0

# global environment variables
ENV LC_ALL C.UTF-8
ENV LANG C.UTF-8
ENV TZ America/New_York
ENV USER root

# get common ubuntu packages that all containers must have, and
# setup gosu binary to modify user permissions in the container
RUN set -eux; \
    DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        gettext-base \
        gosu \
        sudo \
        && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/* && \
    # verify that the binary works
    gosu nobody true



RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        pigz \
        ssh \
        htop \
        vim \
        && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*
