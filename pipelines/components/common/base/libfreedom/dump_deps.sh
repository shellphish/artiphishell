#!/bin/bash

# set -x
# set -e

LIB_DIR="${LIB_DIR:-/shellphish/libfreedom/lib/}"
INTERP_DIR="${INTERP_DIR:-/shellphish/libfreedom/interp/}"
BIN_DIR="${BIN_DIR:-/shellphish/libfreedom/bin/}"
mkdir -p "$LIB_DIR" "$BIN_DIR" "$INTERP_DIR"
LIB_DIR=$(realpath "$LIB_DIR")
BIN_DIR=$(realpath "$BIN_DIR")
INTERP_DIR=$(realpath "$INTERP_DIR")

# Rebased library and interpreter dir, default to LIB_DIR and INTERP_DIR
REBASED_BIN_DIR="${REBASED_BIN_DIR:-$BIN_DIR}"
REBASED_LIB_DIR="${REBASED_LIB_DIR:-$LIB_DIR}"
REBASED_INTERP_DIR="${REBASED_INTERP_DIR:-$INTERP_DIR}"

function rebase_elf() {
    path="$1"
    echo "Rebasing ELF: $(realpath $path)"
    # check if its an ELF, if not, skip
    local is_elf=$(file "$(realpath $path)" | grep 'ELF')
    if [ -z "$is_elf" ]; then
        echo "    (skipped) $path is not an ELF"
        return
    fi
    # check if it's statically linked, if so, skip
    local dyn_executable=$(ldd "$path" 2>&1 | grep 'not a dynamic executable')
    if [ -n "$dyn_executable" ]; then
        echo "    (skipped) $path is statically linked"
        return
    fi
    local REQUESTED_INTERP=$(readelf -l "$path" 2>/dev/null | grep 'Requesting program interpreter' | sed 's/.*interpreter: \(.*\)\]/\1/')
    local INTERP_NAME=$(basename "$REQUESTED_INTERP")
    patchelf --force-rpath --set-rpath '$ORIGIN/../bin' "$path"
    
    # if it's an executable, set the interpreter
    if [ -n "$REQUESTED_INTERP" ]; then
        local INTERP_PATH="$REBASED_INTERP_DIR/$INTERP_NAME"
        if [ -f "$INTERP_PATH" ]; then
            patchelf --set-interpreter "$INTERP_PATH" "$path"
        else
            echo "WARNING: Interpreter $INTERP_PATH not found"
        fi
    fi

}

function relocate_elf() {
    local in_path="$1"
    local out_dir="$2"
    local out_path="$out_dir/$(basename "$in_path")"
    local real_path="$in_path"
    if [ -f "$out_path" ]; then
        # ensure the md5sums match
        if [ "$(md5sum "$in_path" | awk '{print $1}')" == "$(md5sum "$out_path" | awk '{print $1}')" ]; then
            echo "    (skipped) $(basename $in_path) -> $out_path"
            return
        else
            echo "WARNING: $out_path already exists and has different contents"
            exit 1
        fi
    fi

    if [ -L "$in_path" ]; then
        local real_path=$(readlink -f "$in_path")
        cp -u -n "$real_path" "$out_dir/"
        # make a symlink if the link basename and real basename differ
        if [ "$(basename "$real_path")" != "$(basename "$in_path")" ]; then
            ln -s "$out_dir/$(basename "$real_path")" "$out_dir/$(basename "$in_path")"
        fi
    else
        cp -n "$in_path" "$out_dir/"
    fi

    echo "  $in_path -> $out_path"

    # if it's an ELF, get dependencies
    if ! file "$(realpath $in_path)" | grep 'ELF'; then
        echo "    (skipped) $in_path is not an ELF"
        return
    fi

    # if it's statically linked, skip
    local dyn_executable=$(ldd "$in_path" 2>&1 | grep 'not a dynamic executable')
    if [ -n "$dyn_executable" ]; then
        echo "    (skipped) $in_path is statically linked"
        return
    fi

    local INTERPRETER=$(readelf -l "$in_path" 2>/dev/null | grep 'Requesting program interpreter' | sed 's/.*interpreter: \(.*\)\]/\1/')
    if [ -n "$INTERPRETER" ]; then
        add_interpreter "$INTERPRETER"
    fi

    # linux-vdso.so.1 (0x00007ffff7fc1000)
    # libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007ffff7e44000)
    # libpython3.10.so.1.0 => /lib/x86_64-linux-gnu/libpython3.10.so.1.0 (0x00007ffff786d000)
    # libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007ffff7644000)
    # /lib64/ld-linux-x86-64.so.2 (0x00007ffff7fc3000)
    # libexpat.so.1 => /lib/x86_64-linux-gnu/libexpat.so.1 (0x00007ffff7613000)
    # libz.so.1 => /lib/x86_64-linux-gnu/libz.so.1 (0x00007ffff75f7000)
    # echo ldd "$in_path" "|" grep '.so' "|" sed 's/.* => \([^(]*\).*$/\1/g' "|" sed 's/^\s*\([^(]*\).*/\1/g' "|" grep -v 'linux-vdso.so'
    local DEPS=$(ldd "$in_path" | grep '.so' | sed 's/.* => \([^(]*\).*$/\1/g' | sed 's/^\s*\([^(]*\).*/\1/g' | grep -v 'linux-vdso.so')
    # echo "Relocating $in_path: $DEPS"
    local dep
    for dep in $DEPS; do
        if [ -f "$dep" ]; then
            add_library "$dep"
        fi
    done
    # echo "Done relocating $in_path"
}

function add_library() {
    local library="$1"
    # echo "Adding library: $library"
    relocate_elf "$library" "$BIN_DIR"
}
function add_interpreter() {
    local interpreter="$1"
    # echo "Adding interpreter: $interpreter"
    relocate_elf "$interpreter" "$INTERP_DIR"
}

function add_binary() {
    local binary="$1"
    # echo "Adding binary: $binary"
    relocate_elf "$binary" "$BIN_DIR"
}

# set -x

for binary in "$@"; do
    add_binary "$binary"
done
for binary in $(ls "$BIN_DIR"); do
    if [ "$binary" == "afl-clang-fast" ]; then
        set -x
    fi
    rebase_elf "$BIN_DIR/$binary"
    if [ "$binary" == "afl-clang-fast" ]; then
        set +x
    fi
done
for library in $(ls "$LIB_DIR"); do
    rebase_elf "$LIB_DIR/$library"
done

# exit 1