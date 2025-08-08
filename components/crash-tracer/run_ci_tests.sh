#!/bin/bash

set -x

cd $(dirname $0)/.

../../.github/ci_test_component.py crash-tracer $@
