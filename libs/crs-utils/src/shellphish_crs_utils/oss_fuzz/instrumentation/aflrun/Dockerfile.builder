ARG BASE_IMAGE=
ARG PREBUILD_IMAGE=

FROM ${PREBUILD_IMAGE} AS prebuild
FROM ${BASE_IMAGE} AS final-builder


# ---------- 1. host-side prerequisites ---------------------------------------
RUN apt-get update && apt-get install -y software-properties-common


ENV SRC=/src
RUN mkdir -p $SRC/shellphish
COPY --from=prebuild $SRC/shellphish/aflrun $SRC/shellphish/aflrun

# ld.lld has to be named as ld.lld
COPY --from=prebuild $SRC/shellphish/aflrun $SRC/shellphish/aflrun
RUN mkdir -p /llvm
COPY --from=prebuild /llvm/clang+llvm-15.0.0-x86_64-linux-gnu-rhel-8.4.tar.xz /llvm/clang+llvm-15.0.0-x86_64-linux-gnu-rhel-8.4.tar.xz

# ---------- 2. install llvm from the copied clang archive --------------------
RUN tar -xf /llvm/clang+llvm-15.0.0-x86_64-linux-gnu-rhel-8.4.tar.xz -C /llvm 
RUN rm /llvm/clang+llvm-15.0.0-x86_64-linux-gnu-rhel-8.4.tar.xz

ENV PATH="/llvm/clang+llvm-15.0.0-x86_64-linux-gnu-rhel-8.4/bin:$PATH"

RUN mkdir -p /usr/lib/llvm-15/bin && \
    ln -sf /llvm/clang+llvm-15.0.0-x86_64-linux-gnu-rhel-8.4/bin/clang     /usr/lib/llvm-15/bin/clang  && \
    ln -sf /llvm/clang+llvm-15.0.0-x86_64-linux-gnu-rhel-8.4/bin/clang++   /usr/lib/llvm-15/bin/clang++ && \
    ln -sf /llvm/clang+llvm-15.0.0-x86_64-linux-gnu-rhel-8.4/bin/ld.lld    /usr/lib/llvm-15/bin/ld.lld


# ---------- 4. keep the real linker and drop the wrapper in its place ---------
#   * save the genuine lld binary           → $SRC/shellphish/aflrun/real_ldldd
#   * install the wrapper as /usr/lib/llvm-15/bin/ld.lld
#   * give the wrapper a way to invoke the real linker: /usr/bin/ld.real    
RUN mkdir -p $SRC/shellphish/aflrun/real_ldldd && \
    cp  /usr/bin/ld   \
        $SRC/shellphish/aflrun/real_ldldd/ld.lld

COPY anti-wrap-ld.sh /usr/bin/ld
RUN chmod +x /usr/bin/ld && \
    ln -sf $SRC/shellphish/aflrun/real_ldldd/ld.lld /usr/bin/ld.real

COPY compile_aflrun /usr/local/bin/