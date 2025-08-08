#!/bin/bash

set -x

sudo mkdir -p /shared/injected-seeds/
sudo chmod 777 /shared/injected-seeds/

SCRIPT_DIR=$(dirname $0)

cp $SCRIPT_DIR/seeds/* /shared/injected-seeds/.

ls -la /shared/injected-seeds/
