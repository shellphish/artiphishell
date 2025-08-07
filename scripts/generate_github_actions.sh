#!/usr/bin/env bash

IMAGE_PREFIX="ghcr.io/aixcc-sc/asc-crs-shellphish/"
cd "$(dirname "$0")/../pipelines" || { echo "huh?" && exit 1; }

buildme() {
    # $1 should be relative to the pipelines root
    cat <<EOF
          - context: ./crs/${1}
            dockerfile: ./crs/${1}/${2}
            image: ${IMAGE_PREFIX}${3}
EOF
}

pwd="$(pwd)"
find "${pwd}/components" -name 'Dockerfile*' | while read -r dockerfile; do
    context_path="$(dirname "$dockerfile")"
    context_path="${context_path##${pwd}/}"
    image_without_tag="$(grep "aixcc-build:" "$dockerfile" | cut -d: -f2 | grep -o '[^ ]*')"
    if [[ -z "$image_without_tag" ]]; then
        continue
    fi
    dockerfile="$(basename "$dockerfile")"
    buildme "$context_path" "$dockerfile" "$image_without_tag"
done

while true; do
    read -r _ image || break
    read -r _ context || break
    read -r _ dockerfile || break
    buildme "apis/$context" "$dockerfile" "$image"
done < <(grep -E 'image:|context:|dockerfile:' apis/docker-compose.yaml | cut -d# -f1)

buildme . ./meta-components/leader-scripts/Dockerfile aixcc-leader
