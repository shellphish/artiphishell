#!/usr/bin/env bash

INPUT="HELLO WORLD"

pdl --unlock || rm -rf pipeline.lock

pdl
echo $INPUT | pd inject start_time_task.target_id 1
pd --verbose --debug-trace run
pd status

TIME_FILE=/tmp/time.yaml
pd cat start_time_task.start_time 1 > $TIME_FILE
cat $TIME_FILE

if [ "$(cat $TIME_FILE | yq '.target_id')" == "1" ] && [ "$(cat $TIME_FILE | yq '.time')" ]; then
    echo "Success!"
    exit 0
else
    echo "Failure!"
    exit 1
fi
