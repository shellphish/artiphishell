FROM python:3.10-slim

RUN pip install litellm
RUN pip install 'litellm[proxy]'

COPY config.yaml /app/config.yaml
WORKDIR /app
EXPOSE 4000

CMD ["litellm", "--config", "config.yaml", "--port", "4000"]

