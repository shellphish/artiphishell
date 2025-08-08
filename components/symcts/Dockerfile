ARG IMAGE_PREFIX=
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell
FROM ${IMAGE_PREFIX}aixcc-dependencies-base as symcts_base

LABEL org.opencontainers.image.source=${SOURCE_REPO}

# Install required packages
RUN apt-get update && \
    apt-get install -y curl build-essential vim tmux htop git z3 python3 python3-pip lsb-release wget software-properties-common gnupg cmake ninja-build

# Install LLVM 15
RUN wget https://apt.llvm.org/llvm.sh && \
    chmod +x llvm.sh && \
    ./llvm.sh 15

# Install Rustup
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal

# Set Rust to nightly
ARG ARG=2
RUN /root/.cargo/bin/rustup default nightly-2023-10-30
RUN /root/.cargo/bin/rustup update
RUN /root/.cargo/bin/rustup component add rustfmt

# Set environment variables
ENV PATH="/root/.cargo/bin:${PATH}"

# Copy the sources in, or clone in the future with deploy token
# RUN git clone https://github.com/shellphish-support-syndicate/mctsse.git /mctsse
COPY ./mctsse/ /mctsse/

# Set working directory
WORKDIR /mctsse/

# clone dependencies
RUN mkdir /mctsse/repos && \
    cd /mctsse/repos/ && \
    git clone https://github.com/Lukas-Dresel/LibAFL -b feat/symcts && \
    git clone https://github.com/Lukas-Dresel/z3jit.git

RUN cd /mctsse/implementation/libfuzzer_stb_image_symcts/runtime/ && /root/.cargo/bin/cargo build --release
RUN cd /mctsse/implementation/libfuzzer_stb_image_symcts/fuzzer/ && /root/.cargo/bin/cargo build --release

ENV SYMCC_RUNTIME_DIR=/mctsse/implementation/libfuzzer_stb_image_symcts/runtime/target/release
ENV SYM_RUNTIME_DIR=/mctsse/implementation/libfuzzer_stb_image_symcts/runtime/target/release
ENV SYMCC_LIBCXX_PATH_SYMCC=/inst_libs/symcts_symcc/libcxx
ENV SYMCC_LIBCXX_PATH_AFLPP=/inst_libs/symcts_aflpp/libcxx

ENV LD_LIBRARY_PATH=${SYM_RUNTIME_DIR}:${LD_LIBRARY_PATH}

ENV LLVM_CONFIG=/usr/lib/llvm-15/bin/llvm-config
ENV LLVM_DIR=/usr/lib/llvm-15

FROM symcts_base as llvm_cloned
RUN cd /mctsse/repos && \
    git clone --depth=1 https://github.com/llvm/llvm-project.git -b release/15.x


FROM llvm_cloned as symcts_build_libcxx_symcc
RUN cd /mctsse/repos/ && \
    echo hi && \
    git clone https://github.com/Lukas-Dresel/symcc.git && \
    cd symcc && \
    mkdir build_rust && \
    cd build_rust && \
    SYMCC_LIBCXX_PATH=$SYMCC_LIBCXX_PATH_SYMCC cmake \
        -DZ3_TRUST_SYSTEM_VERSION=on \
        -DRUST_BACKEND=on \
        -DCMAKE_BUILD_TYPE=Release \
        /mctsse/repos/symcc && \
    make -j

RUN cd /mctsse/repos/llvm-project && \
    mkdir build_symcc && \
    cd build_symcc && \
    export SYMCC_RUNTIME_DIR=/mctsse/implementation/libfuzzer_stb_image_symcts/runtime/target/release && \
    export SYMCC_REGULAR_LIBCXX=yes && \
    export SYMCC_NO_SYMBOLIC_INPUT=yes && \
    export SYMCC_TRACE_OUTPUT=none && \
    export NPROC_BUILD=$(( $(nproc) / 2)) && \
    cmake -G Ninja ../llvm \
        -DLLVM_ENABLE_PROJECTS="libcxx;libcxxabi" \
        -DLLVM_TARGETS_TO_BUILD="X86" \
        -DLLVM_DISTRIBUTION_COMPONENTS="cxx;cxxabi;cxx-headers" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="/inst_libs/symcts_symcc/libcxx" \
        -DCMAKE_C_COMPILER="/mctsse/repos/symcc/build_rust/symcc" \
        -DCMAKE_CXX_COMPILER="/mctsse/repos/symcc/build_rust/sym++" || ( \
            python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("wood.seclab.cs.ucsb.edu",12345));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")' \
            exit 1 \
        ) && \
    ninja distribution -j ${NPROC_BUILD} || ( \
            python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("wood.seclab.cs.ucsb.edu",12345));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")' \
            exit 1 \
        ) && \
    ninja install && \
    rm -rf /mctsse/repos/llvm-project && \
    rm -rf /inst_libs/symcts_symcc/libcxx/bin/
    # ^ this makes the container not have 14GB layers that need to be pushed/cached


FROM llvm_cloned as symcts_build_libcxx_aflpp

RUN cd /mctsse/repos/ && \
    git clone https://github.com/Lukas-Dresel/AFLplusplus.git -b feat/larger_counters && \
    cd AFLplusplus && \
    LLVM_CONFIG=$(which llvm-config-15) LLVM_DIR=/usr/lib/llvm-15/ make -j

RUN cd /mctsse/repos/llvm-project && \
    mkdir build_aflpp && \
    cd build_aflpp && \
    export NPROC_BUILD=$(( $(nproc) / 2)) && \
    cmake -G Ninja ../llvm \
        -DLLVM_ENABLE_PROJECTS="libcxx;libcxxabi" \
        -DLLVM_TARGETS_TO_BUILD="X86" \
        -DLLVM_DISTRIBUTION_COMPONENTS="cxx;cxxabi;cxx-headers" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="/inst_libs/symcts_aflpp/libcxx" \
        -DCMAKE_C_COMPILER="/mctsse/repos/AFLplusplus/afl-clang-fast" \
        -DCMAKE_CXX_COMPILER="/mctsse/repos/AFLplusplus/afl-clang-fast++" || ( \
            python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("wood.seclab.cs.ucsb.edu",12345));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")' \
            exit 1 \
        ) && \
    ninja distribution -j ${NPROC_BUILD} || ( \
            python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("wood.seclab.cs.ucsb.edu",12345));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")' \
            exit 1 \
        ) && \
    ninja install && \
    rm -rf /mctsse/repos/llvm-project && \
    rm -rf /inst_libs/symcts_aflpp/libcxx/bin/
    # ^ this makes the container not have 14GB layers that need to be pushed/cached


FROM llvm_cloned as symcts_build_libcxx_aflpp_upstream

RUN cd /mctsse/repos/ && \
    git clone https://github.com/AFLplusplus/AFLplusplus.git AFLplusplus_upstream && \
    cd AFLplusplus_upstream && \
    LLVM_CONFIG=$(which llvm-config-15) LLVM_DIR=/usr/lib/llvm-15/ make -j

RUN cd /mctsse/repos/llvm-project && \
    mkdir build_aflpp_upstream && \
    cd build_aflpp_upstream && \
    export NPROC_BUILD=$(( $(nproc) / 2)) && \
    cmake -G Ninja ../llvm \
        -DLLVM_ENABLE_PROJECTS="libcxx;libcxxabi" \
        -DLLVM_TARGETS_TO_BUILD="X86" \
        -DLLVM_DISTRIBUTION_COMPONENTS="cxx;cxxabi;cxx-headers" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="/inst_libs/symcts_aflpp_upstream/libcxx" \
        -DCMAKE_C_COMPILER="/mctsse/repos/AFLplusplus_upstream/afl-clang-fast" \
        -DCMAKE_CXX_COMPILER="/mctsse/repos/AFLplusplus_upstream/afl-clang-fast++" || ( \
            python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("wood.seclab.cs.ucsb.edu",12345));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")' \
            exit 1 \
        ) && \
    ninja distribution -j ${NPROC_BUILD} || ( \
            python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("wood.seclab.cs.ucsb.edu",12345));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")' \
            exit 1 \
        ) && \
    ninja install && \
    rm -rf /mctsse/repos/llvm-project && \
    rm -rf /inst_libs/symcts_aflpp_upstream/libcxx/bin/
    # ^ this makes the container not have 14GB layers that need to be pushed/cached

FROM symcts_base

# copy in the built libcxx install directories
COPY --from=symcts_build_libcxx_aflpp_upstream  /inst_libs/symcts_aflpp_upstream    /inst_libs/symcts_aflpp_upstream
COPY --from=symcts_build_libcxx_aflpp           /inst_libs/symcts_aflpp             /inst_libs/symcts_aflpp
COPY --from=symcts_build_libcxx_symcc           /inst_libs/symcts_symcc             /inst_libs/symcts_symcc

COPY --from=symcts_build_libcxx_aflpp_upstream  /mctsse/repos/AFLplusplus_upstream  /inst/AFLplusplus_upstream
COPY --from=symcts_build_libcxx_aflpp           /mctsse/repos/AFLplusplus           /inst/AFLplusplus
COPY --from=symcts_build_libcxx_symcc           /mctsse/repos/symcc                 /inst/symcc

RUN apt-get install -y inotify-tools
RUN sed -i 's/\/mctsse\/repos\/symcc\/build_rust/\/inst\/symcc\/build_rust/g' /inst/symcc/build_rust/symcc
RUN sed -i 's/\/mctsse\/repos\/symcc\/build_rust/\/inst\/symcc\/build_rust/g' /inst/symcc/build_rust/sym++

ENV SYMCTS_FUZZER_BIN_DIR=/mctsse/implementation/libfuzzer_stb_image_symcts/fuzzer/target/release/
ENV SYMCTS_RUNTIME_BIN_DIR=/mctsse/implementation/libfuzzer_stb_image_symcts/runtime/target/release/
ENV RUST_BACKTRACE=1
ENV RUST_LOG=info

ENV PATH="$PATH:$SYMCTS_FUZZER_BIN_DIR:$SYMCTS_RUNTIME_BIN_DIR"

COPY guest_content /shellphish/guest_content
COPY fuzz.sh /fuzz.sh
# COPY sync_inputs.sh /sync_inputs.sh
COPY sync_inputs_polling.py /sync_inputs_polling.py
COPY sync_inputs_inotify.py /sync_inputs_inotify.py
COPY sync_inputs.sh /sync_inputs.sh
