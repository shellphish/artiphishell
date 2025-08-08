FROM ghcr.io/berriai/litellm:main-v1.63.14-stable

COPY proxy_server_config.yaml /app/proxy_server_config.yaml

COPY mods/litellm/ /app/litellm/
COPY mods/litellm/ /usr/lib/python3.13/site-packages/litellm/
COPY mods/model_prices_and_context_window.json /app/model_prices_and_context_window.json

ENV LITELLM_LOCAL_MODEL_COST_MAP=True

