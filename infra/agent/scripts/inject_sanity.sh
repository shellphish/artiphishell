#!/bin/bash

set -ex

export TEMP=/pdt/

TMPDIR=$(mktemp -d /pdt/tmp.XXXXXX)

echo "This is a test" > $TMPDIR/sanity_check_input.txt
tar -czf $TMPDIR/sanity_check_input.tar.gz $TMPDIR/sanity_check_input.txt

pd inject sanity_check.sanity_check_input_path 1 < $TMPDIR/sanity_check_input.tar.gz


cat > /tmp/fake_crs_task.yaml <<EOF
deadline: 1787179337000
focus: challenge-004-full-nginx-source
harnesses_included: true
metadata:
  round.id: local-dev
  task_id: 5fb0e1b7-ff19-4423-9a61-4340720c21b2
pdt_task_id: 5fb0e1b7ff1944239a614340720c21b2
project_name: nginx
source:
- sha256: 9fbb204a323de141e84bf990bfba4084ff41f1ab8705ed0de0523470aabb9dfc
  type: repo
  url: https://artiphishellci.blob.core.windows.net/targets/9fbb204a323de141e84bf990bfba4084ff41f1ab8705ed0de0523470aabb9dfc.tar.gz?se=2025-05-13T23%3A35%3A32Z&sp=r&sv=2022-11-02&sr=b&sig=xbBlFOUAVdcJrPw1AVDETaiJTdIlwSxE3yyV21EfCbA%3D
- sha256: 9ccb69a13a5745b9c4eff1a4f5d6ac368d12ee6d735d53c72e45226f84260071
  type: fuzz-tooling
  url: https://artiphishellci.blob.core.windows.net/targets/9ccb69a13a5745b9c4eff1a4f5d6ac368d12ee6d735d53c72e45226f84260071.tar.gz?se=2025-05-13T23%3A35%3A35Z&sp=r&sv=2022-11-02&sr=b&sig=zsiWbgA3Le82YViw5F7xRAes%2FWsW%2FFcxG%2F2CQMxCmWM%3D
task_id: 5fb0e1b7-ff19-4423-9a61-4340720c21b2
task_sanitizer: address
task_uuid: 5fb0e1b7-ff19-4423-9a61-4340720c21b2
type: full
fuzzing_pool_name: task1
EOF

pd inject sanity_check.project_id 1 < /tmp/fake_crs_task.yaml
