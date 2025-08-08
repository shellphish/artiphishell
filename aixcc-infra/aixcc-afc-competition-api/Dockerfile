# aixcc-build: aixcc-afc-competition-api
ARG IMAGE_PREFIX=
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell
FROM ${IMAGE_PREFIX}aixcc-libs:latest AS libs
FROM ${IMAGE_PREFIX}aixcc-dependencies-base:latest

WORKDIR /app

# Make a virtual environment and install the dependencies
RUN python -m venv /app/venv
ENV PATH /app/venv/bin:$PATH

COPY --from=libs /libs/crs-utils /app/libs/crs-utils
RUN pip install -e /app/libs/crs-utils

ADD . /app
RUN pip install .

CMD ["/app/run_competition_api.sh"]
