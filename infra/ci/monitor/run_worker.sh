#!/bin/bash

set -ex

NAME="cluster-$DEPLOYMENT_NAME-$(date +%s)"

TOKEN="$(curl "https://shellphish-support-syndicate-workers.cf-a92.workers.dev/api/v1/github/worker/join?token=$CI_WORKER_TOKEN&ip=127.0.0.1&name=$NAME")"

LABELS="cluster-$DEPLOYMENT_NAME,jit,k8s"

./config.sh \
  --url https://github.com/shellphish-support-syndicate \
  --token $TOKEN \
  --unattended \
  --name $NAME \
  --labels "$LABELS"

# Run the runner in background and tee output to a log file
LOG_FILE="/tmp/runner_${NAME}.log"
(./run.sh 2>&1 | tee "$LOG_FILE") &
RUNNER_PID=$!

# Monitor the log file for connection errors
while kill -0 $RUNNER_PID 2>/dev/null; do
    if grep -q "Runner connect error" "$LOG_FILE" 2>/dev/null; then
        echo "Runner connect error detected, terminating runner and related processes"
        pkill -P $RUNNER_PID
        kill $RUNNER_PID
        break
    fi
    sleep 5
done

# Wait for the runner process to finish
wait $RUNNER_PID
echo "Runner process finished"
