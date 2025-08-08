#!/bin/bash

set -eu
# wrapper for clang, clang++ and ld that filters out `-gline-tables-only`, `-gline-directives-only`, `-gno-inline-line-tables` and `-gno-embed-source` flags

# echo "$0 $@" >> /work/wrapper.log

# remove the flags
args=()
has_debug=0
for arg in "$@"; do
  if [[ "$arg" == "-gline-tables-only" ]] || [[ "$arg" == "-gline-directives-only" ]] || [[ "$arg" == "-gno-inline-line-tables" ]] || [[ "$arg" == "-gno-embed-source" ]]; then
    continue
  fi

  # Check for optimization flags and replace with -O0
  if [[ "$arg" =~ ^-O[0-9]$ ]]; then
    arg="-O0"
  fi

  # Replace -g with -ggdb if found
  if [[ "$arg" == "-g" ]] || [[ "$arg" == "-ggdb" ]]; then
    arg="-ggdb3"
    has_debug=1
  fi

  args+=("$arg")
done

# Add -ggdb if no debug flag was present
if [[ $has_debug -eq 0 ]]; then
  args+=("-ggdb3")
fi


# find the original binary and run it
cur_cmd="$0"
binary="$(readlink -f "$0").real"
# echo "REWRITTEN COMMAND: $binary ${args[@]}" >> /work/wrapper.log
if [[ ! -f "$binary" ]]; then
  echo "Error: $binary not found" >&2
  echo "Error: $binary not found" >&2 >> /work/wrapper.log
  exit 1
fi

exec -a "$cur_cmd" "$binary" "${args[@]}"