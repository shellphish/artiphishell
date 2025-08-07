
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

export CFLAGS="-fPIE"
export CXXFLAGS="-fPIE"
export CXX="$SCRIPT_DIR/symcc/build/sym++"
export CC="$SCRIPT_DIR/symcc/build/symcc"
export SYMCC_OUTPUT_DIR="/tmp/results"
export SYMCC_REGULAR_LIBCXX=yes
