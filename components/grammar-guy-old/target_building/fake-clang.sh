#!/bin/bash

# clang wrapper, to be used in the grammar fuzzing pipeline

# first, if a flag called --grammar-guy-things exists, remove it from the arguments
mkdir -p /work/compilation_cache/
# set -x 

GRAMMAR_GUY_MODE=0
ARGS=()
for i in "$@"; do
    if [[ $i == "--grammar-guy-things" ]]; then
        GRAMMAR_GUY_MODE=1
    else
        ARGS+=("$i")
    fi
done

echo "Arguments: ${ARGS[@]}"

if [[ $GRAMMAR_GUY_MODE -eq 1 ]]; then
    echo "Grammar guy mode activated"
    echo "Arguments: ${ARGS[@]}"
    # we are in grammar guy mode, log all c files with their absolute paths into the compilation cache
    for i in "${ARGS[@]}"; do
        if [[ $i == *.c ]] || [[ $i == *.cpp ]] || [[ $i == *.cc ]] || [[ $i == *.cxx ]]; then
            full_path=$(realpath "$i")
            relative_path=$(realpath --relative-to=/ "$full_path")
            echo "Logging for $i: with full: $full_path and relative path: $relative_path"
            mkdir -p "$(dirname /work/compilation_cache/$relative_path)"
            cp "$i" "/work/compilation_cache/$relative_path"
        fi
    done
fi

# now, call the original clang if argv[0] is clang else call the original clang++
if [[ $(basename $0) == "clang" ]]; then
    "$(which clang)" "${ARGS[@]}"
else
    "$(which clang++)" "${ARGS[@]}"
fi
