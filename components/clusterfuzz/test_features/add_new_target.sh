#!/bin/bash

set -x
set -e
set -u

CUR_DIR=$(dirname $(realpath "${0}"))
RESOURCE_DIR=$CUR_DIR/fuzz_harness

if [ $# -lt 1 ]; then
	echo "Usage: $0 <target_dir>"
	exit 1
fi
TARGET_DIR="$1"


if [ ! -d "$TARGET_DIR" ]; then
	echo "$TARGET_DIR is not a valid directory"
	exit 1
fi

if [ ! -f "${TARGET_DIR}/build.sh" ]; then
	echo "No build.sh inside $TARGET_DIR"
	exit 1
elif [ ! -f "${TARGET_DIR}/project.yaml" ]; then
	echo "No project.yaml inside $TARGET_DIR"
	exit 1
elif [ ! -f "${TARGET_DIR}/Dockerfile" ]; then
	echo "No Dockerfile inside $TARGET_DIR"
	exit 1
fi

if [ $# -ge 2 ]; then
	SHORT="$2"
	echo "Using nickname $SHORT"
else
	read -p "Give your target a nickname: " SHORT
fi

if [ $# -ge 3 ]; then
	HARNESS="$3"
	echo "Using harness $HARNESS"
else
	read -p "Whats the harness name: " HARNESS 
fi

echo "Here's what's gonna happen"
echo "Target location : $TARGET_DIR"
echo "Target nickname : $SHORT"
echo "Target harness : $HARNESS"

NAME="$(basename $TARGET_DIR)"

tar -czf "$RESOURCE_DIR/$NAME.tar.gz" -C "$TARGET_DIR" .
echo "$SHORT,$NAME,$HARNESS" >> $CUR_DIR/targets.csv

cat $CUR_DIR/targets.csv | sort -u > /tmp/foo
mv /tmp/foo $CUR_DIR/targets.csv
