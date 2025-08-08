#!/bin/bash

set -ex

pkill -f 'pd viz' -9 || true
(setsid pd viz --host 0.0.0.0 --port 5555 > /tmp/pd_viz.log 2>&1 </dev/null) &
disown

