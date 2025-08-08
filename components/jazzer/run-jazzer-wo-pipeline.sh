#!/bin/bash
# Usage: ./script.sh <jazzer_type> <harness_name> <crashes_dir> <seeds_dir> [shell_san]
#   jazzer_type: either "original" or "shellphish"
#   harness_name: the harness to run (e.g., FuzzerCPV1)
#   crashes_dir: directory for crashing seeds
#   seeds_dir: directory for benign seeds
#   shell_san (optional): if provided and equals "losan", sets SHELL_SAN to "LOSAN"

if [ "$#" -lt 4 ]; then
    echo "Usage: $0 <jazzer_type> <harness_name> <crashes_dir> <seeds_dir> [shell_san]"
    exit 1
fi

JAZZER_TYPE="$1"
HARNESS_NAME="$2"
CRASHES_DIR="$3"
SEEDS_DIR="$4"
USER_SHELL_SAN="$5"

export MODE=fuzz

if [ "$JAZZER_TYPE" = "libfuzzer" ]; then
    export ARTIPHISHELL_JAZZER_BINARY="/out/jazzer_driver.orig"
    export ARTIPHISHELL_JAZZER_AGENT="/out/jazzer_agent_deploy.jar.orig"
elif [ "$JAZZER_TYPE" = "shellphish" ]; then
    export ARTIPHISHELL_JAZZER_BINARY="/shellphish/jazzer-aixcc/jazzer-build/jazzer_driver"
    export ARTIPHISHELL_JAZZER_AGENT="/shellphish/jazzer-aixcc/jazzer-build/jazzer_agent_deploy.jar"
    if [ "$USER_SHELL_SAN" = "losan" ]; then
        export SHELL_SAN="LOSAN"
    fi
else
    echo "Invalid jazzer type. Use 'libfuzzer' or 'shellphish'."
    exit 1
fi

export JAZZER_CONFIG_FILE="/shellphish/jazzer_fuzzing_configs.yaml"
export IN_SCOPE_CLASSES="/shellphish/packages_in_scope.json"
export ARTIPHISHELL_JAZZER_CRASHING_SEEDS="$CRASHES_DIR"
export ARTIPHISHELL_JAZZER_BENIGN_SEEDS="$SEEDS_DIR"
export CORPUS_DIR="$SEEDS_DIR"

# create dis
mkdir -p $ARTIPHISHELL_JAZZER_CRASHING_SEEDS $ARTIPHISHELL_JAZZER_BENIGN_SEEDS

# Save the computed environment variables to an env file.
envfile="envfile"
cat <<EOF > "$envfile"
MODE=$MODE
ARTIPHISHELL_JAZZER_BINARY=$ARTIPHISHELL_JAZZER_BINARY
ARTIPHISHELL_JAZZER_AGENT=$ARTIPHISHELL_JAZZER_AGENT
JAZZER_CONFIG_FILE=$JAZZER_CONFIG_FILE
IN_SCOPE_CLASSES=$IN_SCOPE_CLASSES
ARTIPHISHELL_JAZZER_CRASHING_SEEDS=$ARTIPHISHELL_JAZZER_CRASHING_SEEDS
ARTIPHISHELL_JAZZER_BENIGN_SEEDS=$ARTIPHISHELL_JAZZER_BENIGN_SEEDS
CORPUS_DIR=$ARTIPHISHELL_JAZZER_BENIGN_SEEDS
EOF

# Append SHELL_SAN if it was set
if [ -n "$SHELL_SAN" ]; then
    echo "SHELL_SAN=$SHELL_SAN" >> "$envfile"
fi

echo "Environment file saved to '$envfile'. Run oss-fuzz-fuzz with additional args:"
echo 'oss-fuzz-fuzz ... --docker-args="--env-file=envfile"'
