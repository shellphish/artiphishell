#!/bin/bash

# This script will check to see how many agent pods are running
# then let the user select one of them

# If they don't select one in 20 seconds just choose the first one

rm -f /tmp/selected_agent_pod || true

AGENT_PODS=$(kubectl get pods -l support.shellphish.net/pod-group=pydatatask-agent -o jsonpath='{.items[*].metadata.name}')

if [ -z "$AGENT_PODS" ]; then
    echo "No agent pods found, please connect to a cluster"
    exit 1
fi

# Convert space-separated pod names to array and sort them
IFS=' ' read -ra PODS_ARRAY <<< "$AGENT_PODS"
SORTED_PODS=($(printf '%s\n' "${PODS_ARRAY[@]}" | sort))

# If there's only one pod, use it directly without prompting
if [ "${#SORTED_PODS[@]}" -eq 1 ]; then
    SELECTED_POD="${SORTED_PODS[0]}"
    echo "Using single available pod: $SELECTED_POD"
else
    echo "Available agent pods:"
    for i in "${!SORTED_PODS[@]}"; do
        echo "$((i+1)). ${SORTED_PODS[i]}"
    done

    echo -n "Select a pod (1-${#SORTED_PODS[@]}) or press Enter for default [1]: "
    read -t 20 SELECTION

    # Default to 1 if no selection or timeout
    if [ -z "$SELECTION" ]; then
        SELECTION=1
    fi

    # Validate selection
    if ! [[ "$SELECTION" =~ ^[0-9]+$ ]] || [ "$SELECTION" -lt 1 ] || [ "$SELECTION" -gt "${#SORTED_PODS[@]}" ]; then
        echo "Invalid selection, using first pod"
        SELECTION=1
    fi

    SELECTED_POD="${SORTED_PODS[$((SELECTION-1))]}"
    echo "Selected pod: $SELECTED_POD"
fi

echo "$SELECTED_POD" > /tmp/selected_agent_pod
