#!/usr/bin/env bash
set -x
set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
SCRIPT_PARENT_DIR=$(dirname $SCRIPT_DIR)
ARTIPHISHELL_ROOT="$SCRIPT_PARENT_DIR/"
PATCH_TESTING=${PATCH_TESTING:-}
trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT

DO_PDL_UNLOCK="${DO_PDL_UNLOCK:=true}"

# Setup Services
source "$SCRIPT_DIR/start_services.sh"
# Source environment variables
source "$SCRIPT_DIR/env.sh"
sleep 10 # give some time for the services to actually start

docker images

if [ "${USE_COMPETITION_SERVICE:-false}" = true ]; then
    source $SCRIPT_DIR/run_generate_challenge.sh 

    setup_challenge $TARGET_URL $PROJECT_NAME $USE_COMPETITION_SERVICE $BASE_COMMIT $REFERENCE_COMMIT
fi


pushd $SCRIPT_PARENT_DIR

sudo mkdir -p /shared/
sudo chmod 777 /shared/

sudo mkdir -p /shared/injected-seeds/
sudo chmod 777 /shared/injected-seeds/

if [ "$DO_PDL_UNLOCK" ==  "true" ]
then
    pdl --unlock || rm -rf pipeline.lock
fi
pdl --no-lockstep ${PDL_ARGS:-} --name CRS
echo "$PRE_RUN_EXEC"
if [ "$SHOULD_PD_INJECT" == "true" ] && [ ! -z "$PRE_RUN_EXEC" ]; then
    eval "$PRE_RUN_EXEC"
fi

EXTRA_ENV=${EXTRA_ENV:-}

OUT_PATH=/tmp/pydatatask-$(whoami)-agent-output-$(date +'%Y-%m-%d-%H-%M-%S')

sudo mkdir -p /shared/
sudo chmod 777 /shared/

sudo mkdir -p /shared/injected-seeds/
sudo chmod 777 /shared/injected-seeds/

if [ ! -z "${PATCH_TESTING}" ]; then
    EXTRA_ENV="$EXTRA_ENV -t analyze_target -t bear_build -t clang_index -t clang_index_by_commit -t antlr4_commit_java_parser -t antlr4_full_java_parser -t oss_fuzz_project_build -t poiguy -t povguy -t harness_info_splitter -t build_configuration_splitter -t generate_full_function_index -t generate_commit_function_index -t diff_mode_create_analysis_source -t full_mode_create_analysis_source -t canonical_build -t aflpp_build -t aflpp_fuzz_merge -t debug_build"
    SHOULD_INJECT="true"
fi

# Get environment arguments
ENV_ARGS=$(generate_env_args)

echo $EXTRA_ENV
pd $EXTRA_ENV $ENV_ARGS 1>$OUT_PATH 2>&1 &
AGENT_PID=$!
echo $AGENT_PID > /tmp/pdt-run-id

# Check if SHOULD_INJECT == "true"
if [ "$SHOULD_INJECT" == "true" ]; then
     echo "Injecting crash..."
    ./local_run/inject_crash.sh $PROJECT_NAME &
    EXTRA_ENV="$EXTRA_ENV --global-script-env \"ARTIPHISHELL_GLOBAL_ENV_INJECT_SEEDS=true\""
fi

if [ ! -z "${RESTORE_BACKUP:-}" ]; then
    pd restore "$RESTORE_BACKUP" --all
fi

#if [ -d "${ARTIPHISHELL_ROOT}" ]; then
#pushd "${ARTIPHISHELL_ROOT}"
#    set -ex
#    cd "${ARTIPHISHELL_ROOT}"
#    pd viz --port 45912
#popd
#fi

#/bin/bash ./local_run/ci_fix_docker_created.bash &


export USE_LLM_API=1
ENV_ARGS=$(generate_env_args)

# Add --forever flag only if RUN_FOREVER environment variable is set to "true"
EXTRA_FLAGS=""
if [ "${RUN_FOREVER:-false}" = "true" ]; then
    EXTRA_FLAGS="--forever"
fi

# Disable fuzzing tasks if ARVO_NO_FUZZ is set to true
# Maybe disable some of the permanently
# "aflpp_fuzz_merge"
DISABLE_TASKS=(
    "submitter" "grammar_agent_explore" "run_codechecker"
    "grammar_guy_fuzz" "grammar_guy_fuzz_sarif" "grammar_composer_run" "corpus_trace"
) 
if [ "${ARVO_NO_FUZZ:-false}" = "true" ]; then
    # List of tasks to disable
    DISABLE_TASKS+=(
        "aflrun_fuzz" "aflrun_build"
        "jazzer_fuzz_shellphish" "jazzer_fuzz_merge" "jazzer_fuzz_shellphish_codeql" "jazzer_fuzz" "jazzer_fuzz_same_node_sync"
        "aflpp_fuzz" "aflpp_cross_node_sync" "aflpp_build" "aflpp_trigger_upscale" "aflpp_build_cmplog" "aflpp_fuzz_main_replicant"
        "griller_harnesser" "griller_fuzz" "griller_build"
        "aijon_build" "aijon_fuzz" "aijon_instrument_from_codeswipe" "aijon_instrument_from_diff"
        "coverage_trace"
        "discovery_guy_from_ranking_full"
    )
fi

if [ "${ARVO_TEST:-false}" = "true" ]; then
    if [ -n "${ENABLED_TASKS_LIST[*]}" ]; then
        for TASK in "${ENABLED_TASKS_LIST[@]}"; do
            if [ ! -z "$TASK" ]; then
                EXTRA_ENV="$EXTRA_ENV -t $TASK"
            fi
        done
        EXTRA_ENV="$EXTRA_ENV -t oss_fuzz_project_build --enable-task-dependencies"
    else
        for TASK in "${DISABLE_TASKS[@]}"; do
            if [ ! -z "$TASK" ]; then
                EXTRA_ENV="$EXTRA_ENV -T $TASK"
            fi
        done
    fi
fi

ipython --pdb -m pydatatask.cli.main -- $EXTRA_ENV $ENV_ARGS --verbose --debug-trace run $EXTRA_FLAGS

if [ ! -f /tmp/pdt_magic ]; then
    kill -INT $AGENT_PID
fi
wait

if [ -f $ARTIPHISHELL_ROOT/local_run/.crs-api.pid ]; then
    kill -INT $(cat $ARTIPHISHELL_ROOT/local_run/.crs-api.pid)
    rm $ARTIPHISHELL_ROOT/local_run/.crs-api.pid
fi

# Check for each instance of jinja2.exceptions.UndefinedError and show context
grep -B 10 'jinja2.exceptions.UndefinedError' $OUT_PATH | while read -r line; do
    if [[ $line == *"jinja2.exceptions.UndefinedError"* ]]; then
        # Print the accumulated context and error
        echo "::error::Found jinja2.exceptions.UndefinedError with context:"
        echo "$CONTEXT"
        echo "$line"
        FOUND_ERROR=1
    else
        # Accumulate context
        CONTEXT="$CONTEXT"$'\n'"$line"
    fi
done

if [ "$FOUND_ERROR" = "1" ]; then
    exit 1
fi

popd
