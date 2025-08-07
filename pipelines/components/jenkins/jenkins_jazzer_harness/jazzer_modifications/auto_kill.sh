#!/bin/bash

# Function to get the PID of the directly launched main process
get_direct_main_process_pid() {
    # This uses pgrep with a regular expression that excludes processes containing 'timeout'
    pgrep -f "^/classpath/jazzer/jazzer.bin"
}

# Function to kill direct child processes of a given parent PID
kill_child_processes() {
    local parent_pid=$1
    local child_pids=$(ps --ppid $parent_pid -o pid= | tr -d ' ')

    if [ -n "$child_pids" ]; then
        echo "Killing child processes of PID $parent_pid: $child_pids"
        kill $child_pids
    else
        echo "No child processes found for PID $parent_pid."
    fi
}

# Main logic to find and kill child processes, running in a loop
main() {
    while true; do
        echo "Current process tree:"
        #ps auxf --forest
        local main_pid=$(get_direct_main_process_pid)

        if [ -n "$main_pid" ]; then
            echo "Directly launched main process found with PID: $main_pid"
            kill_child_processes $main_pid
        else
            echo "Directly launched main process '/classpath/jazzer/jazzer.bin' not found."
        fi

        # Sleep for a specified number of seconds before checking again
        sleep 5  # Adjust the sleep duration as needed
    done
}

# Start the main function
main



