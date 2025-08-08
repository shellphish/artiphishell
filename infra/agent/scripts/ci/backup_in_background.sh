#!/bin/bash

SCRIPT_DIR=$(realpath $(dirname $0)/..)

cd $SCRIPT_DIR

# Use setsid to create a new session and detach from terminal
# Use disown to remove process from shell's job control
# Redirect all output to log file
(setsid $SCRIPT_DIR/ci/backup.sh $@ >> /tmp/backup.log 2>&1 </dev/null) & 
disown

sleep 10
