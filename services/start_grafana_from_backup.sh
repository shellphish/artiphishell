#!/usr/bin/bash

DB_TAR_LOCATION=$1
SERVICES_FOLDER=$(dirname $(realpath $0))

if [ -z "$DB_TAR_LOCATION" ]; then
    echo "Usage: $0 <db_tar_location>"
    exit 1
fi

tar -xvzf $DB_TAR_LOCATION -C /tmp/
filename=telemetry_db
DB_FOLDER=/tmp/${filename%.tar.gz}

pushd $SERVICES_FOLDER/telemetry_db
docker compose down -v
docker compose up -d
docker cp $DB_FOLDER telemetry_db:/telemetry_db_backup
sleep 10
docker exec telemetry_db influx restore /telemetry_db_backup --full
popd

pushd $SERVICES_FOLDER/grafana
docker compose down -v
docker compose up -d
popd
