#! /bin/bash

set -e

LOCAL_USER=${LOCAL_USER:-1000:1000}
BASH="bash"

if [[ "${LOCAL_USER}" != "0:0" ]]; then
	# extract user and group from the variable
	LOCAL_USER_ID=${LOCAL_USER%:*}
	LOCAL_USER_GID=${LOCAL_USER#*:}

	mkdir -p /home/appuser
	groupadd -o -g "${LOCAL_USER_GID}" appuser 2>/dev/null
	useradd -o -m -g "${LOCAL_USER_GID}" -u "${LOCAL_USER_ID}" -d /home/appuser appuser 2>/dev/null

	chown -R appuser:appuser /home/appuser /var/log/capi

	export HOME=/home/appuser
	BASH="gosu appuser bash"
fi

$BASH -c "cd competition_api && poetry run alembic upgrade head && cd -"
$BASH -c "poetry run prestart"
$BASH -c "poetry run uvicorn competition_api.main:app --host 0.0.0.0 --port ${AIXCC_PORT:-8080} --workers ${WEB_CONCURRENCY:-4}"
