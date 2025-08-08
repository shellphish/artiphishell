#!/bin/bash

set -ex

curl -u $COMPETITION_API_KEY_ID:$COMPETITION_API_KEY_TOKEN \
    https://binary-blade.tasker.aixcc.tech/crs/url/

sleep 10

function start_integeration_test() {
    curl -u $COMPETITION_API_KEY_ID:$COMPETITION_API_KEY_TOKEN \
        -X POST \
        https://binary-blade.tasker.aixcc.tech/v1/request/delta/
}

function task_libpng() {
curl -u $COMPETITION_API_KEY_ID:$COMPETITION_API_KEY_TOKEN \
-X POST \
https://binary-blade.tasker.aixcc.tech/webhook/trigger_task \
-H 'Content-Type: application/json' \
-d '{
    "challenge_repo_url": "git@github.com:aixcc-finals/example-libpng.git",
    "challenge_repo_base_ref": "0cc367aaeaac3f888f255cee5d394968996f736e",
    "challenge_repo_head_ref": "fdacd5a1dcff42175117d674b0fda9f8a005ae88",
    "fuzz_tooling_url": "https://github.com/aixcc-finals/oss-fuzz-aixcc.git",
    "fuzz_tooling_ref": "d5fbd68fca66e6fa4f05899170d24e572b01853d",
    "fuzz_tooling_project_name": "libpng",
    "duration": 7200
}'
}

function task_zookeeper() {
curl -u $COMPETITION_API_KEY_ID:$COMPETITION_API_KEY_TOKEN \
-X POST \
https://binary-blade.tasker.aixcc.tech/webhook/trigger_task \
-H 'Content-Type: application/json' \
-d '{
    "challenge_repo_url": "git@github.com:aixcc-finals/afc-zookeeper.git",
    "challenge_repo_base_ref": "d19cef9ca254a4c1461490ed8b82ffccfa57461d",
    "challenge_repo_head_ref": "5ee4f185d0431cc88f365ce779aa04a87fe7690f",
    "fuzz_tooling_url": "https://github.com/aixcc-finals/oss-fuzz-aixcc.git",
    "fuzz_tooling_ref": "challenge-state/zk-ex1-delta-01",
    "fuzz_tooling_project_name": "zookeeper",
    "duration": 7200
}'
}

function task_libxml2() {
curl -u $COMPETITION_API_KEY_ID:$COMPETITION_API_KEY_TOKEN \
-X POST \
https://binary-blade.tasker.aixcc.tech/webhook/trigger_task \
-H 'Content-Type: application/json' \
-d '{
    "challenge_repo_url": "git@github.com:aixcc-finals/afc-libxml2.git",
    "challenge_repo_base_ref": "792cc4a1462d4a969d9d38bd80a52d2e4f7bd137",
    "challenge_repo_head_ref": "9d1cb67c31933ee5ae3ee458940f7dbeb2fde8b8",
    "fuzz_tooling_url": "https://github.com/aixcc-finals/oss-fuzz-aixcc.git",
    "fuzz_tooling_ref": "challenge-state/lx-ex1-delta-01",
    "fuzz_tooling_project_name": "libxml2",
    "duration": 7200
}'
}

start_integeration_test
