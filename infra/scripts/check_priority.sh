#!/usr/bin/env bash

ARTIPHISHELL_DIR=$(dirname $(dirname $(dirname $(realpath $0))))

# Arrays to store tasks with and without priorities
declare -A tasks_with_priority
declare -A tasks_without_priority

# Generate list of yaml files from both directories
component_files=$(find $ARTIPHISHELL_DIR/components -maxdepth 2 -type f -name "*.yaml")
pipeline_files=$(find $ARTIPHISHELL_DIR/pipelines -type f -name "*.yaml")

# Combine the lists and process each file
for yaml_file in $component_files $pipeline_files; do
    # Extract tasks and their priorities
    tasks=$(yq '.tasks' $yaml_file | yq -r 'keys[]') || echo "Error: $yaml_file failed to parse"
    for task in $tasks; do
        priority=$(yq ".tasks.$task.priority" $yaml_file)
        # Convert absolute path to relative path
        relative_path=${yaml_file#$ARTIPHISHELL_DIR/}
        if [ "$priority" = "null" ] || [ -z "$priority" ]; then
            tasks_without_priority["$task"]="$relative_path"
        else
            tasks_with_priority["$task"]="$priority"
        fi
    done
done

# Print all tasks with priorities, sorted by priority value
if [ ${#tasks_with_priority[@]} -gt 0 ]; then
    echo "Tasks with priorities:"
    echo "Task Name | Priority"
    echo "----------|----------"
    # Sort by priority value (numeric)
    for task in $(for k in "${!tasks_with_priority[@]}"; do echo "${tasks_with_priority[$k]}|$k"; done | sort -n -r | cut -d'|' -f2); do
        printf "%-40s | %s\n" "$task" "${tasks_with_priority[$task]}"
    done | column -t -s '|'
fi

# Print tasks without priorities
if [ ${#tasks_without_priority[@]} -gt 0 ]; then
    echo -e "\nWARNING: The following tasks have no priority set:"
    echo "Task Name | File Location"
    echo "----------|--------------"
    for task in $(for k in "${!tasks_without_priority[@]}"; do echo "$k"; done | sort -V); do
        printf "%-40s | %s\n" "$task" "${tasks_without_priority[$task]}"
    done | column -t -s '|'
fi