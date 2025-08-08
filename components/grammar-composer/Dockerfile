# aixcc-build: aixcc-grammar-composer

# this image comes with crs-utils
# to build aixcc-component-base locally cd to shellphish-crs/pipelines/local_run and run rebuild_local.sh

ARG IMAGE_PREFIX=
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell

####################################################################################################
####################################################################################################
FROM ${IMAGE_PREFIX}aixcc-component-base as grammar-composer-base
LABEL org.opencontainers.image.source=${SOURCE_REPO}

RUN python3 -m venv --system-site-packages /venv
ENV PATH="/venv/bin:$PATH"
ENV VIRTUAL_ENV=/venv
# NOTE: this builds nautilus as-is in the base image
# NOTE: in the devcontainer we build nautilus again on postStart
RUN pip3 install maturin[patchelf]
RUN maturin develop --release --strip --manifest-path /shellphish/libs/nautilus/nautilus_python/Cargo.toml

RUN pip3 install pyyaml
COPY . /shellphish/grammar-composer/
RUN pip3 install -e /shellphish/grammar-composer/
