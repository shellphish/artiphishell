#!/bin/bash
set -x

# Define an array of volume names to backup
VOLUME_NAMES=("signoz-zookeeper-1" "signoz-clickhouse" "signoz-alertmanager" "signoz-sqlite")

mkdir -p /shared/signoz-backup
# Loop through each volume and create a backup
for VOLUME_NAME in "${VOLUME_NAMES[@]}"; do
  echo "Backing up volume: $VOLUME_NAME"
    docker run --rm \
        -v "$VOLUME_NAME":/backup-volume \
        -v "/shared/signoz-backup":/backup \
        ubuntu:22.04 \
        tar --owner=1000 --group=1000 -zcf /backup/$VOLUME_NAME-backup.tar.gz /backup-volume
done

tar --owner=1000 --group=1000 -zcf /shared/signoz-backup.tar.gz /shared/signoz-backup
echo "Backup completed. You can find the backups in the signoz-backup directory."