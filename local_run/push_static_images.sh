#!/bin/bash

export EXTERNAL_REGISTRY=${EXTERNAL_REGISTRY:-}

(
docker pull ghcr.io/shellphish-support-syndicate/competition-test-api:v1.1-rc4
docker tag ghcr.io/shellphish-support-syndicate/competition-test-api:v1.1-rc4 ${EXTERNAL_REGISTRY}/competition-test-api:v1.1-rc4
docker push ${EXTERNAL_REGISTRY}/competition-test-api:v1.1-rc4
) &

(
docker pull alpine:latest
docker tag alpine:latest ${EXTERNAL_REGISTRY}/alpine:latest
docker push ${EXTERNAL_REGISTRY}/alpine:latest
) &

(
docker pull neo4j:latest
docker tag neo4j:latest ${EXTERNAL_REGISTRY}/neo4j:latest
docker push ${EXTERNAL_REGISTRY}/neo4j:latest
) & 

(
docker pull postgres:15-alpine
docker tag postgres:15-alpine ${EXTERNAL_REGISTRY}/postgres:15-alpine
docker push ${EXTERNAL_REGISTRY}/postgres:15-alpine
) &

(
docker pull python:3.12-slim 
docker tag python:3.12-slim ${EXTERNAL_REGISTRY}/python:3.12-slim
docker push ${EXTERNAL_REGISTRY}/python:3.12-slim
) &

(
docker pull ubuntu:latest
docker tag ubuntu:latest ${EXTERNAL_REGISTRY}/ubuntu:latest
docker push ${EXTERNAL_REGISTRY}/alpine:latest
) &

(
docker pull docker:28-dind
docker tag docker:28-dind ${EXTERNAL_REGISTRY}/docker:28-dind
docker push ${EXTERNAL_REGISTRY}/docker:28-dind
) &

(
docker pull clickhouse/clickhouse-server:24.1.2-alpine
docker tag clickhouse/clickhouse-server:24.1.2-alpine ${EXTERNAL_REGISTRY}/clickhouse-server:24.1.2-alpine
docker push ${EXTERNAL_REGISTRY}/clickhouse-server:24.1.2-alpine
) &

(
docker pull bitnami/zookeeper:3.7.1
docker tag bitnami/zookeeper:3.7.1 ${EXTERNAL_REGISTRY}/zookeeper:3.7.1
docker push ${EXTERNAL_REGISTRY}/zookeeper:3.7.1
) &

(
docker pull signoz/alertmanager:0.23.7
docker tag signoz/alertmanager:0.23.7 ${EXTERNAL_REGISTRY}/alertmanager:0.23.7
docker push ${EXTERNAL_REGISTRY}/alertmanager:0.23.7
) &

(
docker pull signoz/query-service:0.71.0
docker tag signoz/query-service:0.71.0 ${EXTERNAL_REGISTRY}/query-service:0.71.0
docker push ${EXTERNAL_REGISTRY}/query-service:0.71.0
) &

wait

(
docker pull signoz/frontend:0.71.0
docker tag signoz/frontend:0.71.0 ${EXTERNAL_REGISTRY}/frontend:0.71.0
docker push ${EXTERNAL_REGISTRY}/frontend:0.71.0
) &

(
docker pull signoz/signoz-otel-collector:0.111.26
docker tag signoz/signoz-otel-collector:0.111.26 ${EXTERNAL_REGISTRY}/signoz-otel-collector:0.111.26
docker push ${EXTERNAL_REGISTRY}/signoz-otel-collector:0.111.26
) &

(
docker pull gliderlabs/logspout:v3.2.14
docker tag gliderlabs/logspout:v3.2.14 ${EXTERNAL_REGISTRY}/logspout:v3.2.14
docker push ${EXTERNAL_REGISTRY}/logspout:v3.2.14
) &

(
docker pull signoz/signoz-schema-migrator:0.111.24
docker tag signoz/signoz-schema-migrator:0.111.24 ${EXTERNAL_REGISTRY}/signoz-schema-migrator:0.111.24
docker push ${EXTERNAL_REGISTRY}/signoz-schema-migrator:0.111.24
) &

(
docker pull busybox:latest
docker tag busybox:latest ${EXTERNAL_REGISTRY}/busybox:latest
docker push ${EXTERNAL_REGISTRY}/busybox:latest
) &

(
docker pull docker:dind
docker tag docker:dind ${EXTERNAL_REGISTRY}/docker:dind
docker push ${EXTERNAL_REGISTRY}/docker:dind
) &

(
docker pull redis:7-alpine
docker tag redis:7-alpine ${EXTERNAL_REGISTRY}/redis:7-alpine
docker push ${EXTERNAL_REGISTRY}/redis:7-alpine
) &

wait
