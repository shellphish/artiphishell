ARG BASE_IMAGE=
FROM ${BASE_IMAGE}

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y software-properties-common clang clang-tidy cppcheck g++ build-essential curl gcc-multilib git python3 python3-dev python3-venv python3-setuptools bear

RUN python3 -m venv $SRC/shellphish/codechecker-venv && \
    . $SRC/shellphish/codechecker-venv/bin/activate && \
    pip install codechecker

# codechecker wants diagtool in the same directory as clang, 
# but oss-fuzz/base-clang compiles clang, save it in /usr/local/bin,
# and manually removed diagtool from the directory
# https://github.com/google/oss-fuzz/blob/master/infra/base-images/base-clang/checkout_build_install_llvm.sh
# NOTE: The version of diagtool doesn't need to match the clang version
RUN if [ ! -f /usr/local/bin/diagtool ]; then ln -s $(ls -d /usr/lib/llvm-* | sort -V | tail -n1)/bin/diagtool /usr/local/bin/diagtool; fi

COPY generic_harness.c $SRC/shellphish/
COPY compile_codechecker /usr/local/bin/
RUN cp /usr/local/bin/compile /usr/local/bin/compile.old
COPY compile /usr/local/bin/compile
