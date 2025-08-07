# checkov:skip=CKV_DOCKER_2:This is a oneshot that doesn't host anything; no healthcheck necessary
FROM grafana/xk6:0.11.0 as xk6

WORKDIR /tmp

RUN xk6 build v0.51.0 \
    --with github.com/szkiba/xk6-yaml@v0.1.4

FROM alpine:3.20

RUN addgroup -S appuser
RUN adduser -S appuser  -G appuser

COPY --from=xk6 /tmp/k6 /k6

WORKDIR /app

COPY loadtest_config.yaml loadtest_config.yaml
COPY script.js script.js
COPY capi capi
COPY index.js index.js

USER appuser

ENTRYPOINT ["/k6"]
CMD ["run", "script.js"]
