#!/bin/bash

# Startup script for Permanence Service

# Set default environment variables if not already set
export PERMANENCE_STORAGE_ROOT=${PERMANENCE_STORAGE_ROOT:-"$(pwd)/permanence_storage"}
export PERMANENCE_DB_PATH=${PERMANENCE_DB_PATH:-"$(pwd)/permanence.db"}
export PERMANENCE_API_SECRET=${PERMANENCE_API_SECRET:-"!!artiphishell!!"}
export PERMANENCE_HOST=${PERMANENCE_HOST:-"0.0.0.0"}
export PERMANENCE_PORT=${PERMANENCE_PORT:-"8000"}

# Create storage directory if it doesn't exist
mkdir -p "$PERMANENCE_STORAGE_ROOT"

echo "Starting Permanence Service..."
echo "Storage path: $PERMANENCE_STORAGE_ROOT"
echo "Database path: $PERMANENCE_DB_PATH"
echo "API secret: ${PERMANENCE_API_SECRET:0:3}*****"
echo "Listening on: $PERMANENCE_HOST:$PERMANENCE_PORT"

# Run the service
python permanence_service.py