# aixcc-build: aixcc-clang-indexer
ARG IMAGE_PREFIX=
from ubuntu:22.04
LABEL org.opencontainers.image.source=https://github.com/aixcc-sc/asc-crs-shellphish

# install requirements
run apt-get update && apt-get install -y python3 python3-pip curl wget tmux git
run apt-get install -y software-properties-common
run wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc && \
    apt-add-repository "deb http://apt.llvm.org/jammy/ llvm-toolchain-jammy-17 main" && \
    apt-get update && apt-get install -y libclang1-17
run pip install GitPython jsonschema joblib
copy . /clang_indexer
RUN tar xvf /clang_indexer/clang-indexer-cache.tgz -C / && \
    rm /clang_indexer/clang-indexer-cache.tgz

run git config --global --add safe.directory '*'
run pip install ./clang_indexer

