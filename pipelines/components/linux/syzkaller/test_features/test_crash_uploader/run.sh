#!/bin/bash

./setup_initial_dirs.sh

ipython --pdb ../../syzkaller_crashes_upload.py ./test_data/input/ ./dir_config.yaml &
pid_monitor=$!

create_at_random_time() {
    sleep $((RANDOM % 10))
    mkdir -p $(dirname $1)
    INPUT=$(cat -)
    echo -n "$INPUT" > $1

}
sleep 2

echo 'report0' | create_at_random_time test_data/input/123456/report0 &
echo 'description 1' | create_at_random_time test_data/input/123456/description &
echo 'log0' | create_at_random_time test_data/input/123456/log0 &

# different order of operations
echo 'log1' | create_at_random_time test_data/input/123457/log1 &
echo 'report1' | create_at_random_time test_data/input/123457/report1 &
echo 'description 2' | create_at_random_time test_data/input/123457/description &

echo '10' | create_at_random_time test_data/crashes/uploaded/123456 &
sleep 1
# now put another log and report into 123456
echo 'report1' | create_at_random_time test_data/input/123456/report1 &
echo 'log1' | create_at_random_time test_data/input/123456/log1 &

echo '20' | create_at_random_time test_data/crashes/uploaded/123457 &
echo 'description 3' | create_at_random_time test_data/input/123458/description &
echo 'report 0' | create_at_random_time test_data/input/123458/report0 &
echo 'log 0' | create_at_random_time test_data/input/123458/log0 &

set -x
sleep 10
echo '30' > test_data/crashes/uploaded/123458
sleep 20

fg $pid_monitor
kill $(jobs -p)