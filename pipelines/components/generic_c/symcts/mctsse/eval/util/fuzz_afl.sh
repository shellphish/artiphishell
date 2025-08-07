#!/bin/bash
set -euo pipefail
set -x

NODE_NAME=$1
case $NODE_NAME in 
	master)
		AFL_ARGS="-M master"
		;;
	slave*)
		AFL_ARGS="-S $NODE_NAME"
		;;
	fairfuzz*)
		AFL_ARGS="-S $NODE_NAME -b -r -q 1"
		;;
	*)
		echo "Unknown node type for node $NODE_NAME" > /dev/stderr
		exit 1;
		;;
esac
shift 1
AFL_ARGS="$AFL_ARGS $@"
FUZZ="$AFL_DIR/afl-fuzz"
unset AFL_DIR
$FUZZ -i ./inputs -o sync $AFL_ARGS -- ./target "$NODE_NAME"
