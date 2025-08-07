#!/usr/bin/env bash
set -e

REMOTE="https://github.com/aixcc-sc/asc-crs-shellphish"
BRANCH="main"

usage() {
    cat <<EOF
Usage: $(tput bold)$0 [CRS_ROOT]$(tput sgr0)

If CRS_ROOT is not provided, CRS_ROOT=/crs in this repository will be removed
and replaced with $REMOTE:$BRANCH

Then, copy a history-nuked pipelines into CRS_ROOT/crs and apply config changes.
EOF
    exit 1
}

case "$1" in
    -h|--help) usage ;;
esac

set -x
SHELLPHISH_ROOT="$(dirname "$0")/.."
PIPELINES_ROOT="$SHELLPHISH_ROOT/pipelines"

if [ -z "$1" ]; then
    CRS_ROOT="$SHELLPHISH_ROOT/crs"
    rm -rf "$CRS_ROOT"
    git clone --branch $BRANCH $REMOTE "$CRS_ROOT"
else
    CRS_ROOT="$(realpath "$1")"
fi

rm -rf "$CRS_ROOT/crs"
cp -r "$PIPELINES_ROOT" "$CRS_ROOT/crs"
find "$CRS_ROOT/crs" \( -name .git -o -name .gitmodules -o -name .gitignore -o -name .gitattributes \) -print0 | xargs -0 rm -rf

COMPOSE_YAML="$CRS_ROOT/compose.yaml"
PACKAGE_YAML="$CRS_ROOT/.github/workflows/package.yml"


LINE_CUSTOMIZE_START="$(cat -n "$COMPOSE_YAML" | grep '### CUSTOMIZE' | awk '{ print $1 }' | head -n1)"
LINE_CUSTOMIZE_END="$(cat -n "$COMPOSE_YAML" | grep '### CUSTOMIZE' | awk '{ print $1 }' | tail -n1)"
LINE_CUSTOMIZE_EOF="$(wc -l <"$COMPOSE_YAML")"

head -n$((LINE_CUSTOMIZE_START + 1)) "$COMPOSE_YAML" >/tmp/compose0
"$SHELLPHISH_ROOT/scripts/generate_docker_compose.sh" >/tmp/compose1
#sed -E -i -e 's/build:/build:\n      cache_from:\n        - type=gha\n      cache_to:\n        - type=gha/g' /tmp/compose1
tail -n$((LINE_CUSTOMIZE_EOF - LINE_CUSTOMIZE_END + 1)) "$COMPOSE_YAML" >/tmp/compose2
cat /tmp/compose0 /tmp/compose1 /tmp/compose2 >"$COMPOSE_YAML"

LINE_INCLUDE_START="$(cat -n "$PACKAGE_YAML" | grep 'include:' | awk '{ print $1 }' | head -n1)"
LINE_INCLUDE_END="$(cat -n "$PACKAGE_YAML" | grep '  permissions:' | awk '{ print $1 }' | head -n1)"
LINE_INCLUDE_EOF="$(wc -l <"$PACKAGE_YAML")"
head -n$((LINE_INCLUDE_START)) "$PACKAGE_YAML" >/tmp/package0
"$SHELLPHISH_ROOT/scripts/generate_github_actions.sh" >/tmp/package1
tail -n$((LINE_INCLUDE_EOF - LINE_INCLUDE_END + 1)) "$PACKAGE_YAML" >/tmp/package2
cat /tmp/package0 /tmp/package1 /tmp/package2 >"$PACKAGE_YAML"
