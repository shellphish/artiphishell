
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

export CFLAGS="-fPIE"
export CXXFLAGS="-fPIE"
export CXX="$SCRIPT_DIR/AFLplusplus/afl-clang-fast++"
export CC="$SCRIPT_DIR/AFLplusplus/afl-clang-fast"
