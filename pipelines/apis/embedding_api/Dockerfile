FROM python:3.8-slim-bullseye
LABEL org.opencontainers.image.source=https://github.com/aixcc-sc/asc-crs-shellphish

WORKDIR /app

COPY ./* /app/

# ENV EMB_MODEL_TYPE=local
ENV EMB_MODEL_TYPE=litellm

RUN pip install --progress-bar off --no-cache-dir -r requirements_${EMB_MODEL_TYPE}.txt
RUN if [ "$EMB_MODEL_TYPE" = "local" ]; then python /app/download_models.py; fi

# These will be given as environment variables
# ENV LITELLM_KEY=sk-artiphishell
# ENV AIXCC_LITELLM_HOSTNAME=http://beatty.unfiltered.seclab.cs.ucsb.edu:4000

CMD ["python", "webapp.py"]