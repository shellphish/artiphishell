# Start from a base image
ARG IMAGE_PREFIX=
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell

FROM ${IMAGE_PREFIX}aixcc-component-base
LABEL org.opencontainers.image.source=${SOURCE_REPO}

WORKDIR /shellphish

ENV DEBIAN_FRONTEND=noninteractive

RUN bash -c "source $HOME/.cargo/env && rustup install 1.76.0 && rustup default nightly-2024-02-04"

WORKDIR /snapchange/QEMU

# # Install Ghidra
# RUN apt -y update && apt install -y --no-install-recommends openjdk-17-jdk wget
# WORKDIR /snapchange/ghidra_stuff
# RUN wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.2.2_build/ghidra_10.2.2_PUBLIC_20221115.zip -O ghidra.zip
# RUN unzip ghidra.zip && rm ghidra.zip && mv ghidra_10* ghidra
# RUN /bin/rm ghidra/Ghidra/Features/Base/ghidra_scripts/DemangleAllScript.java && \
#     /bin/rm ghidra/Ghidra/Features/Base/ghidra_scripts/DemangleSymbolScript.java && \
#     /bin/rm -rf ghidra/Ghidra/Features/GnuDemangler && \
#     /bin/rm -rf ghidra/GPL/DemanglerGnu && \
#     /bin/rm -rf ghidra/Ghidra/Features/MicrosoftDemangler/

# Extra stuff we need for fuzzing
COPY snapchange_modifications /snapchange/snapchange_modifications

# RUN clang -c -o /snapchange_modifications/harness_constructor.o /snapchange_modifications/coverage_harness.c -ggdb -no-pie -fsanitize-coverage=inline-8bit-counters
RUN clang -c -o /snapchange/snapchange_modifications/snapchange_lib.o /snapchange/snapchange_modifications/snapchange_lib.c
RUN ar rcs /snapchange/snapchange_modifications/liblinkagainstharness.a /snapchange/snapchange_modifications/snapchange_lib.o

# Scripts and other stuff
COPY snapchange /snapchange/snapchange/
COPY qemu_stuff /snapchange/qemu_stuff

# A workdir for storing our script and patch files
WORKDIR /workdir

ENV PATH="$HOME/.cargo/bin:${PATH}"
RUN echo "source $HOME/.cargo/env" >> $HOME/.bashrc

# Save some time in game/ci by downloading and compiling dependencies here
RUN export PATH=$PATH:$HOME/.cargo/bin && cd /snapchange/snapchange && cargo build
RUN export PATH=$PATH:$HOME/.cargo/bin && cd /snapchange/snapchange/fuzzer && cargo build || true

COPY run-*.sh /snapchange

COPY fuzz.sh /workdir/

CMD [ "/bin/bash" ]
