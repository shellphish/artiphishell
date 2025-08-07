#!/bin/bash

# This script is used to setup the initial directories for the crash monitor test.

rm -rf test_data
mkdir -p test_data/input
mkdir -p test_data/{crashes,crash_logs,crash_reports}/{data,lock,meta,uploaded}
