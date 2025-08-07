#!/usr/bin/env bash

if [ -z "$IMAGE_PREFIX" ]; then
    echo "PLEASE SPECIFY \$IMAGE_PREFIX" >&2
    exit 1
fi

cd "$(dirname "$0")/../pipelines" || { echo "huh?" && exit 1; }

mandatory_volumes() {
    cat <<EOF
      #################################################################################
      ### THESE VOLUMES MUST BE INCLUDED WITHOUT MODIFICATION TO ALL CRS CONTAINERS ###
      # A CRS MUST copy CP repositories from \`/cp_root\` to a writable location such as \`/crs_scratch\` for building and testing CPs.
      # A CRS MUST not modify settings within this section.
      - type: bind
        source: \${PWD}/crs_scratch
        target: /crs_scratch
        bind:
          propagation: rshared
      - ./cp_root:/cp_root
      #################################################################################
EOF
}

IMAGE_DEPS=""

buildme() {
    IMAGE_DEPS="$IMAGE_DEPS image-${1}"
    cat <<EOF
  image-${1}:
    profiles:
      - development
      - competition
    image: ${IMAGE_PREFIX}${1}:latest
    entrypoint: '/bin/sh -c "if [ -e /selftest ]; then /selftest; else true; fi && echo health check success"'
    restart: no
EOF
}

cat <<EOF

### IMPORTANT NOTE FOR SHELLPHISH ###
### DO NOT modify docker-compose.yaml directly. instead modify the pipelines repo.

volumes:
  mongo-data:
  minio-data:

services:
EOF

pwd="$(pwd)"
find "${pwd}/components" -name 'Dockerfile*'  -not -path "*test*" | while read -r dockerfile; do
    context_path="$(dirname "$dockerfile")"
    context_path="${context_path##${pwd}/}"
    image_without_tag="$(grep "aixcc-build:" "$dockerfile" | cut -d: -f2 | grep -o '[^ ]*')"
    if [[ -z "$image_without_tag" ]]; then
        continue
    fi
    dockerfile="$(basename "$dockerfile")"
    buildme "$image_without_tag" "$context_path" "$dockerfile"
done

echo

#tail -n+4 apis/docker-compose.yaml | sed -E -e 's_\./_./crs/apis/_g' -e "s_image: *_image: ${IMAGE_PREFIX}_g"  # :(
tail -n+4 apis/docker-compose.yaml | grep -Ev 'build:|dockerfile:|context:|args:|KB_NAME' | sed -E -e "s_image: *_image: ${IMAGE_PREFIX}_g"  # :(

cat <<EOF
  crs:
    profiles:
      - development
      - competition
    networks:
      - crs-internal
    image: ${IMAGE_PREFIX}aixcc-leader
    labels:
      kompose.serviceaccount-name: crs
    #build:
    #  context: ./crs
    #  dockerfile: ./meta-components/leader-scripts/Dockerfile
    #  args:
    #    IMAGE_PREFIX: $IMAGE_PREFIX
    entrypoint: /root/pipelines/meta-components/leader-scripts/leader.sh
    privileged: true
    volumes:
EOF
mandatory_volumes
cat <<EOF
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      # These values will be modified automatically at competition time
      - DOCKER_HOST=tcp://dind:2375
      - AIXCC_LITELLM_HOSTNAME=http://litellm
      - AIXCC_API_HOSTNAME=http://iapi:8080
      - AIXCC_CP_ROOT=/cp_root
      - AIXCC_CRS_SCRATCH_SPACE=/crs_scratch
      - LITELLM_KEY=sk-1234
    depends_on:
      iapi:
        condition: service_started
      mongo:
        condition: service_started
      minio:
        condition: service_healthy
EOF
for dep in $IMAGE_DEPS; do
    cat <<EOF
      ${dep}:
        condition: service_completed_successfully
EOF
done
cat <<EOF
  agent:
    networks:
      - crs-internal
    profiles:
      - development
      - competition
    image: ${IMAGE_PREFIX}aixcc-leader
    labels:
      kompose.serviceaccount-name: crs
      kompose.controller.type: daemonset
    entrypoint: /root/pipelines/meta-components/leader-scripts/agent.sh
    privileged: true
    deploy:
      resources:
        reservations:
          cpus: '1'
          memory: 2G
        limits:
          cpus: '1'
          memory: 4G
    volumes:
EOF
mandatory_volumes
cat <<EOF
      - /var/run/docker.sock:/var/run/docker.sock
    depends_on:
      mongo:
        condition: service_started
      minio:
        condition: service_healthy
    ports:
      - "127.0.0.1:9595:9595"
  ingest:
    profiles:
      - development
      - competition
    networks:
      - crs-internal
    image: ${IMAGE_PREFIX}aixcc-leader
    labels:
      kompose.serviceaccount-name: crs
    entrypoint: /root/pipelines/meta-components/leader-scripts/ingest.sh
    privileged: true
    volumes:
EOF
mandatory_volumes
cat <<EOF
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - AIXCC_CP_ROOT=/cp_root
      - AIXCC_CRS_SCRATCH_SPACE=/crs_scratch
    depends_on:
      mongo:
        condition: service_started
      minio:
        condition: service_healthy
  logs:
    profiles:
      - development
      - competition
    networks:
      - crs-internal
    image: ${IMAGE_PREFIX}aixcc-leader
    labels:
      kompose.serviceaccount-name: crs
    entrypoint: '/root/venv/bin/python3 /root/pipelines/meta-components/leader-scripts/logs.py'
    privileged: true
    volumes:
EOF
mandatory_volumes
cat <<EOF
      - /var/run/docker.sock:/var/run/docker.sock
    depends_on:
      mongo:
        condition: service_started
      minio:
        condition: service_healthy

EOF
