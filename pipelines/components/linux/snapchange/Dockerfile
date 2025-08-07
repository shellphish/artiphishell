# aixcc-build: aixcc-snapchange-fuzz

# Start from a base image
ARG IMAGE_PREFIX=

FROM ${IMAGE_PREFIX}aixcc-dependencies-base AS syzlangrs_builder

WORKDIR /shellphish

COPY syzlangrs /shellphish/syzlangrs
RUN cd /shellphish/syzlangrs && ./build.sh
RUN cd /shellphish/syzlangrs/syzlang-bridge && python gen.py

FROM ${IMAGE_PREFIX}aixcc-dependencies-base
LABEL org.opencontainers.image.source=https://github.com/aixcc-sc/asc-crs-shellphish

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get install -y lcov

# Install rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > /tmp/install_rust.sh && \
    chmod +x /tmp/install_rust.sh && \
    /tmp/install_rust.sh --default-toolchain nightly -y && \
    rm /tmp/install_rust.sh

RUN bash -c "source $HOME/.cargo/env && rustup install 1.76.0 && rustup default nightly-2024-02-04"

# # Install Ghidra
# RUN apt -y update && apt install -y --no-install-recommends openjdk-17-jdk wget
# WORKDIR /data_dir/ghidra_stuff
# RUN wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.2.2_build/ghidra_10.2.2_PUBLIC_20221115.zip -O ghidra.zip
# RUN unzip ghidra.zip && rm ghidra.zip && mv ghidra_10* ghidra
# RUN /bin/rm ghidra/Ghidra/Features/Base/ghidra_scripts/DemangleAllScript.java && \
#     /bin/rm ghidra/Ghidra/Features/Base/ghidra_scripts/DemangleSymbolScript.java && \
#     /bin/rm -rf ghidra/Ghidra/Features/GnuDemangler && \
#     /bin/rm -rf ghidra/GPL/DemanglerGnu && \
#     /bin/rm -rf ghidra/Ghidra/Features/MicrosoftDemangler/

# Install QEMU
RUN apt -y install gcc-9 g++-9 clang make ninja-build debootstrap libelf-dev libssl-dev pkg-config
RUN apt -y install libglib2.0-dev libgcrypt20-dev zlib1g-dev autoconf automake libtool bison flex libpixman-1-dev
RUN git clone -b v9.0.1 https://github.com/qemu/QEMU /data_dir/QEMU
WORKDIR /data_dir/QEMU
COPY qemu_stuff/0001-Snapchange-kvm-patches.patch /data_dir/qemu_stuff/0001-Snapchange-patches.patch
RUN patch -p1 < ../qemu_stuff/0001-Snapchange-patches.patch
RUN mkdir build && cd build && ../configure --target-list=x86_64-softmmu --enable-system --enable-slirp --disable-werror && make -j`nproc`

# Rootfs shit
RUN apt -y install unar
COPY initramfs.cpio.gz /data_dir/qemu_stuff/
RUN cd /data_dir/qemu_stuff/ && unar initramfs.cpio.gz && mv initramfs.cpio initramfs

# Install Docker
RUN apt -y install lsb-release software-properties-common
RUN curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
RUN add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
RUN apt-get update && apt-get -y install docker-ce

# Misc
RUN apt -y install cpio

# Grammar
COPY --from=syzlangrs_builder /shellphish/syzlangrs /syzlangrs

# Extra stuff we need for fuzzing
COPY snapchange_modifications /snapchange_modifications

# RUN clang -c -o /snapchange_modifications/harness_constructor.o /snapchange_modifications/coverage_harness.c -ggdb -no-pie -fsanitize-coverage=inline-8bit-counters
RUN clang -c -o /snapchange_modifications/snapchange_lib.o /snapchange_modifications/snapchange_lib.c
RUN ar rcs /snapchange_modifications/liblinkagainstharness.a /snapchange_modifications/snapchange_lib.o

# Scripts and other stuff
COPY snapchange /snapchange
COPY qemu_stuff /data_dir/qemu_stuff

# A workdir for storing our script and patch files
WORKDIR /workdir

ENV PATH="$HOME/.cargo/bin:${PATH}"

RUN echo "source $HOME/.cargo/env" >> $HOME/.bashrc
COPY fuzz.sh /workdir/

CMD [ "/bin/bash" ]
