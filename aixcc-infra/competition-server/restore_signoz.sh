#!/bin/bash
set -ex

SIGNOZ_ZIP_FILE=$1

# Define an array of volume names to backup
VOLUME_NAMES=("signoz-zookeeper-1" "signoz-clickhouse" "signoz-alertmanager" "signoz-sqlite")

tar -zxvf $SIGNOZ_ZIP_FILE -C signoz-backup
# Loop through each volume and create a backup
for VOLUME_NAME in "${VOLUME_NAMES[@]}"; do
  echo "Backing up volume: $VOLUME_NAME"
    docker run --rm \
        -v "$VOLUME_NAME":/backup-volume \
        -v "$(pwd)/signoz-backup":/backup \
        busybox \
        tar -zxvf /backup/$VOLUME_NAME-backup.tar.gz -C /
done