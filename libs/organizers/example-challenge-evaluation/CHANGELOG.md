# Changelog

## v1.2.0

Optional, backwards-compatible flags added to propagate exit
codes on build-cr and run-tests. Added mishandled case in
run-pov for libfuzzer oom (exit code 71).

Version updates:

- build_cr: v1.6.0 -> v1.8.0
- run_tests: v2.3.0 -> v2.4.0
- run_pov: v3.1.0 -> 3.1.1

## v1.1.0

Optional flags have been added to support docker image tag
overrides, reproducing povs with unprivileged docker, and
using a reproduce timeout in case of subprocess hanging.

## v1.0.0

This is the first version of the collection of these scripts  
for sharing with competitors.
