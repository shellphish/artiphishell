#!/bin/bash

curl -u $COMPETITION_API_KEY_ID:$COMPETITION_API_KEY_TOKEN \
    https://binary-blade.tasker.aixcc.tech/crs/url/

curl -u $COMPETITION_API_KEY_ID:$COMPETITION_API_KEY_TOKEN \
    -X PATCH \
    https://binary-blade.tasker.aixcc.tech/crs/url/ \
    -H 'Content-Type: application/json' \
    -d '{"hostname":"binary-blade-test-2-2"}'

curl -u $COMPETITION_API_KEY_ID:$COMPETITION_API_KEY_TOKEN \
    https://binary-blade.tasker.aixcc.tech/crs/url/
