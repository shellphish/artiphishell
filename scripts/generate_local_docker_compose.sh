#!/usr/bin/env bash

IMAGE_PREFIX="${IMAGE_PREFIX:-ghcr.io/shellphish-support-syndicate/}"
DEFAULT_IMAGE_TAG="latest"

cd "$(dirname "$0")/../pipelines" || { echo "huh?" && exit 1; }

cat <<EOF
######################################################################################################
# DO NOT MODIFY THIS FILE ANYWHERE OTHER THAN WITHIN THE CUSTOMIZE BLOCKS
#
#
# New services are acceptable
# Any service which needs KVM or Docker MUST run privleged and pass the appropriate volume (see below)
# /dev/kvm for QEMU or /var/run/docker.sock for Docker
#
# Profiles
# We use the profiles "development" and "competition"
# All containers added by competitors must include the appropriate profiles
# At competition time only the \`--profile competition\` will be used
# This will cause the LiteLLM proxy to disappear.
# Competitors should be using the LITELLM_URL environment variable
# for accessing LiteLLM, so we can swap the URL at competition time.
#
######################################################################################################

# include:
#   - sandbox/docker-compose.yaml

#############
### CUSTOMIZE
#############

### Additional services are welcomed, just make sure to use the supplied variables and profile names

### IMPORTANT NOTE FOR SHELLPHISH ###
### DO NOT modify docker-compose.yaml directly. instead modify the pipelines repo.
### This file was generated based on pipelines $(git rev-parse HEAD)$(if ! git diff-index --quiet HEAD; then echo " (dirty)"; fi)

volumes:
  mongo-data:
  minio-data:

networks:
  crs-internal:

services:
EOF

tail -n+4 apis/docker-compose.yaml | sed -E -e 's_\./_./pipelines/apis/_g' -e "s_image: *_image: ${IMAGE_PREFIX}_g"  # :(

tmpfile="$(mktemp)"

pwd="$(pwd)"
find "${pwd}/components" -name 'Dockerfile*' -not -path "*test*" | while read -r dockerfile; do
    context_path="$(dirname "$dockerfile")"
    context_path="${context_path##${pwd}/}"
    tagme="$(grep "aixcc-build:" "$dockerfile" | cut -d: -f 2- | grep -o '[^ ]*')"
    if [[ -z "$tagme" ]]; then
        continue
    fi
    image_without_tag="$(cut -d: -f1 <<<"$tagme")"
    deps="$(grep -i '^from' "$dockerfile" | cut -d' ' -f2- | cut -d: -f1 | grep IMAGE_PREFIX | cut -d'}' -f2 | cut -d' ' -f1 | sort | uniq | grep -v aixcc-component-base | grep -v aixcc-dependencies-base)"
    dockerfile="$(basename "$dockerfile")"
    if [[ "$image_without_tag" = "$tagme" ]]; then
        image_with_tag=$tagme:$DEFAULT_IMAGE_TAG
    else
        image_with_tag=$tagme
    fi
    cat >>"$tmpfile" <<EOF
  image-${image_without_tag}:
    profiles:
      - local
      - development
      - competition
    image: $IMAGE_PREFIX$image_with_tag
    build:
      args:
        IMAGE_PREFIX: $IMAGE_PREFIX
      context: ./pipelines/$context_path
      dockerfile: $dockerfile
    entrypoint: '/bin/sh -c "if [ -e /selftest ]; then /selftest; else true; fi && echo health check success"'
EOF
done

echo
cat "$tmpfile"
rm "$tmpfile"

cat <<EOF

#############
### CUSTOMIZE
#############
EOF
