#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

pip install -r ${SCRIPT_DIR}/test_oss_fuzz_reports/requirements.txt
pip install -e ${SCRIPT_DIR}/../../../libs/crs-utils/
${SCRIPT_DIR}/test_oss_fuzz_reports/run.py
