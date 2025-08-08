#!/bin/bash

set -x

CLANG_PATH=$(which clang)
CLANGPP_PATH=$(which clang++)
CLANG_18_PATH=$(which clang-18)
GCC_PATH=$(which gcc)
GCC_9_PATH=$(which gcc-9)
X86_64_LINUX_GNU_GCC_9_PATH=$(which x86_64-linux-gnu-gcc-9)
GPP_PATH=$(which g++)
GPP_9_PATH=$(which g++-9)
X86_64_LINUX_GNU_GPP_9_PATH=$(which x86_64-linux-gnu-g++-9)
LD_PATH=$(which ld)
X86_64_LINUX_GNU_LD_PATH=$(which x86_64-linux-gnu-ld)
X86_64_LINUX_GNU_LD_BFD_PATH=$(which x86_64-linux-gnu-ld.bfd)

TO_PATCH=("$CLANG_18_PATH" "$X86_64_LINUX_GNU_GCC_9_PATH" "$X86_64_LINUX_GNU_GPP_9_PATH" "$X86_64_LINUX_GNU_LD_BFD_PATH")

# Make ABSOLUTELY sure that we're patching exactly what we're expecting to patch here
CLANG_LINK=$(readlink "$CLANG_PATH")
if [ "$CLANG_LINK" != "clang-18" ]; then
  echo "Error: $CLANG_PATH is not a symlink to clang-18" >&2
  exit 1
fi
CLANGPP_LINK=$(readlink "$CLANGPP_PATH")
if [ "$CLANGPP_LINK" != "clang" ]; then
  echo "Error: $CLANGPP_PATH is not a symlink to clang++" >&2
  exit 1
fi

GCC_LINK=$(readlink "$GCC_PATH")
if [ "$GCC_LINK" != "gcc-9" ]; then
  echo "Error: $GCC_PATH is not a symlink to gcc-9" >&2
  exit 1
fi
GCC_9_LINK=$(readlink "$GCC_9_PATH")
if [ "$GCC_9_LINK" != "x86_64-linux-gnu-gcc-9" ]; then
  echo "Error: $GCC_9_PATH is not a symlink to x86_64-linux-gnu-gcc-9" >&2
  exit 1
fi

GPP_LINK=$(readlink "$GPP_PATH")
if [ "$GPP_LINK" != "g++-9" ]; then
  echo "Error: $GPP_PATH is not a symlink to g++-9" >&2
  exit 1
fi
GPP_9_LINK=$(readlink "$GPP_9_PATH")
if [ "$GPP_9_LINK" != "x86_64-linux-gnu-g++-9" ]; then
  echo "Error: $GPP_9_PATH is not a symlink to x86_64-linux-gnu-g++-9" >&2
  exit 1
fi

LD_LINK=$(readlink "$LD_PATH")
if [ "$LD_LINK" != "x86_64-linux-gnu-ld" ]; then
  echo "Error: $LD_PATH is not a symlink to x86_64-linux-gnu-ld" >&2
  exit 1
fi
X86_64_LINUX_GNU_LD_LINK=$(readlink "$X86_64_LINUX_GNU_LD_PATH")
if [ "$X86_64_LINUX_GNU_LD_LINK" != "x86_64-linux-gnu-ld.bfd" ]; then
  echo "Error: $X86_64_LINUX_GNU_LD_PATH is not a symlink to x86_64-linux-gnu-ld.bfd" >&2
  exit 1
fi

# check that only clang-18 exists
for i in `seq 10 20`; do
  if [ "$i" -eq 18 ]; then
    continue
  fi
  if [ -x "/usr/local/bin/clang-$i" ]; then
    echo "Error: /usr/local/bin/clang-$i exists" >&2
    exit 1
  fi
done

# check that only gcc-9 exists
for i in `seq 1 15`; do
  if [ "$i" -eq 9 ]; then
    continue
  fi
  if [ -x "/usr/local/bin/gcc-$i" ]; then
    echo "Error: /usr/local/bin/gcc-$i exists" >&2
    exit 1
  fi
done

# patch clang
for binary in "${TO_PATCH[@]}"; do
  # check that the binary is not a symlink
  if [ -L "$binary" ]; then
    link_target=$(readlink "$binary")
    echo "Error: $binary is a symlink to $link_target" >&2
    exit 1
  fi
  if [ -x "$binary" ]; then
    echo "Patching $binary"
    # Add your patching commands here
    mv "$binary" "$binary.real"
    cp /shellphish/wrapper.sh "$binary"
    chmod +x "$binary"
  else
    echo "Binary $binary not found or not executable" >&2
    exit 1
  fi
done

