
#!/bin/bash -u

set -eux

CURR_DIR=$(pwd)
CURR_USER=$(whoami)

./ci_tests/test_zip4j_yajta.sh # BROKEN
./ci_tests/test_zip4j.sh #BROKEN
./ci_tests/test_mupdf.sh
./ci_tests/test_assimp_pin.sh
./ci_tests/test_cups.sh



