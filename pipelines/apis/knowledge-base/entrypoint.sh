#!/bin/sh

mkdir -p "$NEO4J_HOME/conf"
exec /startup/docker-entrypoint.sh "$@"
