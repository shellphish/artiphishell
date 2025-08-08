#!/bin/bash

set -ex

SCRIPT_DIR=$(realpath $(dirname $0))

function generate_challenge_task() {
    local target_url="${1%.git}"
    local project_name="$2" 
    local base_commit="$3"
    local reference_commit="$4"

    if [ -z "$base_commit" ]; then
        base_commit=$(git ls-remote "$target_url" HEAD | cut -f1)
    fi

    CMD="./generate-challenge-task.sh -c localhost:5000 \
        -t \"$target_url\" \
        -b \"$base_commit\" \
        -p \"$project_name\" \
        -l -v"

    CUSTOM_OSS_FUZZ_TARGETS_REPO="${CUSTOM_OSS_FUZZ_TARGETS_REPO:-}"
    if [ ! -z "$CUSTOM_OSS_FUZZ_TARGETS_REPO" ]; then
        CUSTOM_OSS_FUZZ_TARGETS_REPO=$(echo "$CUSTOM_OSS_FUZZ_TARGETS_REPO" | sed 's|git@github.com:|https://github.com/|g')
        mkdir -p $SCRIPT_DIR/.shellphish
        CUSTOM_OSS_FUZZ_REPO="$SCRIPT_DIR/.shellphish/oss-fuzz"
        if [ ! -d "$CUSTOM_OSS_FUZZ_REPO" ]; then
            git clone https://github.com/google/oss-fuzz.git "$CUSTOM_OSS_FUZZ_REPO"
            git clone "$CUSTOM_OSS_FUZZ_TARGETS_REPO" $SCRIPT_DIR/.shellphish/oss-fuzz-targets
            pushd $SCRIPT_DIR/.shellphish/oss-fuzz-targets
                git lfs pull
            popd
            # if SHELLPHISH_OSS_FUZZ_TARGETS_BRANCH is set, checkout that branch
            if [ ! -z "$SHELLPHISH_OSS_FUZZ_TARGETS_BRANCH" ]; then
                pushd $SCRIPT_DIR/.shellphish/oss-fuzz-targets
                    git checkout $SHELLPHISH_OSS_FUZZ_TARGETS_BRANCH
                popd
            fi
            rm -rf $CUSTOM_OSS_FUZZ_REPO/projects/
            cp -r $SCRIPT_DIR/.shellphish/oss-fuzz-targets/projects $CUSTOM_OSS_FUZZ_REPO/projects
            if [ -d "$SCRIPT_DIR/.shellphish/oss-fuzz-targets/ARVO" ]; then
                cp -r $SCRIPT_DIR/.shellphish/oss-fuzz-targets/ARVO/* $CUSTOM_OSS_FUZZ_REPO/projects
            fi
            pushd $CUSTOM_OSS_FUZZ_REPO
                yq e ".shellphish_project_name = \"$PROJECT_NAME\"" -i projects/$PROJECT_NAME/project.yaml
                yq e ".shellphish_docker_image = \"gcr.io/oss-fuzz/$PROJECT_NAME\"" -i projects/$PROJECT_NAME/project.yaml
                # python3 infra/helper.py build_image "$PROJECT_NAME"
                docker build --no-cache --secret id=GITHUB_CRED_URL,src=$HOME/.git-credentials -t gcr.io/oss-fuzz/$PROJECT_NAME --file $SCRIPT_DIR/.shellphish/oss-fuzz/projects/$PROJECT_NAME/Dockerfile $SCRIPT_DIR/.shellphish/oss-fuzz/projects/$PROJECT_NAME
                git add projects
                git commit -m "Add shellphish oss-fuzz targets"
            popd
        fi
        CMD="$CMD -o \"$CUSTOM_OSS_FUZZ_REPO\""
    fi


    if [ ! -z "$REFERENCE_COMMIT" ]; then
        CMD="$CMD -r \"$REFERENCE_COMMIT\""
    fi
    TAR_REPOS=$SCRIPT_DIR/generate-challenge-task/repo-tars

    # Run the generate-challenge-task script
    pushd "$SCRIPT_DIR/generate-challenge-task"
        export CRS_API_KEY_ID=$ARTIPHISHELL_API_USERNAME
        export CRS_API_TOKEN=$ARTIPHISHELL_API_PASSWORD
        rm -rf $TAR_REPOS
        eval $CMD


        # Process the generated tars
        if [ ! -d "$TAR_REPOS" ]; then
            echo "Error: TAR_REPOS directory $TAR_REPOS does not exist" >&2
            exit 1
        fi

        # Find the repo tar and oss-fuzz tar
        repo_tar=$(find "$TAR_REPOS" -name "*.tar.gz" ! -name "oss-fuzz*.tar.gz" ! -name "diff-*.tar.gz" | head -n 1)
        oss_fuzz_tar=$(find "$TAR_REPOS" -name "oss-fuzz*.tar.gz" | head -n 1)
        diff_tar=$(find "$TAR_REPOS" -name "diff-*.tar.gz" | head -n 1)

        # Extract project name from oss-fuzz tar
        project_yaml=""
        temp_dir=$(mktemp -d)
        tar -xzf "$oss_fuzz_tar" -C "$temp_dir"

        # Repackage oss-fuzz tar without the extra directory level
        inner_dir=$(ls "$temp_dir" | head -n 1)
        if [ -d "$temp_dir/$inner_dir" ]; then
            temp_dir2=$(mktemp -d)
            cp -r "$temp_dir/$inner_dir"/* "$temp_dir2/"
            tar -czf "$oss_fuzz_tar" -C "$temp_dir2" .
            rm -rf "$temp_dir2"
        fi

        # Find project.yaml for the specified project name
        yaml_file="$temp_dir/fuzz-tooling/projects/$PROJECT_NAME/project.yaml"
        if [ -f "$yaml_file" ]; then
            project_yaml=$(cat "$yaml_file")
        else
            echo "Error: Could not find project.yaml for project $PROJECT_NAME" >&2
            exit 1
        fi

        # Extract task JSON from task_crs.sh
        task_json=$(grep -o '{.*}' "$SCRIPT_DIR/generate-challenge-task/task_crs.sh" | \
                    jq --arg target_url "$repo_tar" \
                    --arg oss_fuzz_repo "$oss_fuzz_tar" \
                    --arg diff_tar "${diff_tar:-}" \
                    '.tasks[0].task_sanitizer = "address" |
                        .tasks[0].source[0].url = $target_url |
                        .tasks[0].source[1].url = $oss_fuzz_repo |
                        if .tasks[0].source[2] and $diff_tar != "" then .tasks[0].source[2].url = $diff_tar else . end')

        # Loop through each task in the tasks array
        while read -r task; do
            task_id=$(head -c 32 /dev/urandom | sha256sum | awk '{print $1}')
            # Replace task_id in task json with the one without dashes
            task=$(echo "$task" | jq '.task_uuid = .task_id')
            task=$(echo "$task" | jq --arg new_id "$task_id" '.pdt_task_id = $new_id')
            # Build inject commands string
            echo "$task"
            PRE_RUN_EXEC+="echo '$task' | pd inject 'pipeline_input.project_id' '$task_id' && "
            PRE_RUN_EXEC+="echo '$project_yaml' | pd inject 'pipeline_input.project_metadata' '$task_id' && "
            PRE_RUN_EXEC+="cat '$repo_tar' | pd inject 'pipeline_input.project_base_source' '$task_id' && "
            PRE_RUN_EXEC+="cat '$oss_fuzz_tar' | pd inject 'pipeline_input.oss_fuzz_repo' '$task_id'"

            if [ ! -z "$diff_tar" ]; then
                # Extract the diff file from the tar
                temp_diff_dir=$(mktemp -d)
                tar -xzf "$diff_tar" -C "$temp_diff_dir"
                diff_file=$(find "$temp_diff_dir" -type f | head -n 1)
                PRE_RUN_EXEC+=" && cat '$diff_file' | pd inject 'pipeline_input.project_diff' '$task_id'"
            fi
            PRE_RUN_EXEC+=" && echo 'Successfully injected task_id: $task_id';"
        done < <(echo "$task_json" | jq -c '.tasks[]')

        rm -rf "$temp_dir"

        export PRE_RUN_EXEC
    popd
}

function competition_service() {
    local target_url="${1%.git}"
    local project_name="$2" 
    local base_commit="$3"
    local reference_commit="$4"

    rm -f $SCRIPT_DIR/.challenge.json

    if [ -z "$reference_commit" ]; then
        reference_commit=$(git ls-remote "$target_url" HEAD | cut -f1)
    fi

    # --arg fuzz_tooling_url "https://github.com/aixcc-finals/oss-fuzz-aixcc.git" \
    # --arg fuzz_tooling_ref "d5fbd68fca66e6fa4f05899170d24e572b01853d" \

    jq -n \
        --arg target_url "$target_url" \
        --arg reference_commit "$reference_commit" \
        --arg fuzz_tooling_url "https://github.com/shellphish-support-syndicate/artiphishell-ossfuzz-targets.git" \
        --arg fuzz_tooling_ref "main" \
        --arg fuzz_tooling_project_name "$project_name" \
        --argjson duration 3600 \
        '{
            "challenge_repo_url": $target_url,
            "challenge_repo_head_ref": $reference_commit,
            "fuzz_tooling_url": $fuzz_tooling_url,
            "fuzz_tooling_ref": $fuzz_tooling_ref,
            "fuzz_tooling_project_name": $fuzz_tooling_project_name,
            "duration": $duration
        }' > $SCRIPT_DIR/.challenge.json
    
    if [ ! -z "$base_commit" ] && [ "$base_commit" != "$reference_commit" ]; then
        jq --arg base_commit "$base_commit" '.challenge_repo_base_ref = $base_commit' $SCRIPT_DIR/.challenge.json
    fi

    # Set global variables for use by rest of script
    # curl -X 'POST' 'http://localhost:1323/webhook/trigger_task' -L -H 'Content-Type: application/json' -d @$SCRIPT_DIR/.challenge.json
}

function setup_challenge() {
    local target_url="${1%.git}"
    local project_name="$2" 
    local use_competition_service="$3"
    local base_commit="${4:-}"
    local reference_commit="${5:-}"

    GENERATE_CHALLENGE_TASK_REPO="${GENERATE_CHALLENGE_TASK_REPO:=https://github.com/shellphish-support-syndicate/aixcc-afc-generate-challenge-task.git}"
    # Check if generate-challenge-task exists, if not clone it
    if [ ! -d "$SCRIPT_DIR/generate-challenge-task" ]; then
        git clone $GENERATE_CHALLENGE_TASK_REPO "$SCRIPT_DIR/generate-challenge-task"
    fi

    # If base commit is not specified, get HEAD of the target repo
    if [ "$use_competition_service" = true ]; then
        competition_service "$target_url" "$project_name" "$base_commit" "$reference_commit"
        export PRE_RUN_EXEC=""
    else
        generate_challenge_task "$target_url" "$project_name" "$base_commit" "$reference_commit"
    fi
}
