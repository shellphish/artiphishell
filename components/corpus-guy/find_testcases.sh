#!/bin/bash

# FIRST STUFF THAT REALLY LOOKS LIKE CRASHES
rm -f /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*test*/*' -name 'crash*' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*test*/*' -name '*.crash' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*regress*/*' -name 'crash*' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*regress*/*' -name '*.crash' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*corpus*/*' -name 'crash*' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*corpus*/*' -name '*.crash' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*fuzz*/*' -name 'crash*' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*fuzz*/*' -name '*.crash' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*bugs*/*' -name 'crash*' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*bugs*/*' -name '*.crash' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*crash*/*' -name 'crash*' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*crash*/*' -name '*.crash' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*corpora*/*' -name 'crash*' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*corpora*/*' -name '*.crash' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*test*/*' -name 'bug*' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*test*/*' -name '*.bug' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*regress*/*' -name 'bug*' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*regress*/*' -name '*.bug' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*corpus*/*' -name 'bug*' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*corpus*/*' -name '*.bug' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*fuzz*/*' -name 'bug*' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*fuzz*/*' -name '*.bug' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*bugs*/*' -name 'bug*' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*bugs*/*' -name '*.bug' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*crash*/*' -name 'bug*' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*crash*/*' -name '*.bug' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*corpora*/*' -name 'bug*' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*corpora*/*' -name '*.bug' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*test*/*' -name 'poc*' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*test*/*' -name '*.poc' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*regress*/*' -name 'poc*' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*regress*/*' -name '*.poc' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*corpus*/*' -name 'poc*' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*corpus*/*' -name '*.poc' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*fuzz*/*' -name 'poc*' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*fuzz*/*' -name '*.poc' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*bugs*/*' -name 'poc*' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*bugs*/*' -name '*.poc' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*crash*/*' -name 'poc*' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*crash*/*' -name '*.poc' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*corpora*/*' -name 'poc*' >> /tmp/all-crashes.raw &&
find $PWD -type f -path '*/*corpora*/*' -name '*.poc' >> /tmp/all-crashes.raw &&
find $PWD -type f -path "*\/*crash*\/*" -name 'clusterfuzz-testcase-minimized*' >> /tmp/all-crashes.raw &&
find $PWD -type f -path "*\/*bug*\/*" -name 'clusterfuzz-testcase-minimized*' >> /tmp/all-crashes.raw &&
cat /tmp/all-crashes.raw | sort -u > /tmp/all-crashes &&
sed -i '/\.md$/d' /tmp/all-crashes &&
sed -i '/\.yaml$/d' /tmp/all-crashes &&
sed -i '/\.yml$/d' /tmp/all-crashes &&
sed -i '/\.rst$/d' /tmp/all-crashes &&
sed -i '/expected\.txt$/d' /tmp/all-crashes &&
sed -i '/\.summary$/d' /tmp/all-crashes &&
sed -i '/\.diff$/d' /tmp/all-crashes &&
sed -i '/\/patches\/$/d' /tmp/all-crashes &&
sed -i '/\.patch$/d' /tmp/all-crashes &&
sed -i '/\.result$/d' /tmp/all-crashes &&
sed -i '/\.baseline$/d' /tmp/all-crashes &&
sed -i '/\.baseline-jsc$/d' /tmp/all-crashes &&
sed -i '/\.scores$/d' /tmp/all-crashes &&
sed -i '/\.dot$/d' /tmp/all-crashes &&
sed -i '/\.exp$/d' /tmp/all-crashes &&
sed -i '/\.err$/d' /tmp/all-crashes &&
sed -i '/\.out$/d' /tmp/all-crashes


# THEN OTHER TEST CASES
rm -f /tmp/all-tests.raw

# Search patterns for test case files
patterns=("crash" "bug" "poc" "test" "repro" "fail" "testcase" "input" "clusterfuzz-testcase")
directories=("test" "regress" "corpus" "fuzz" "bugs" "crash" "corpora" "testdata" "inputs" "seeds" "cases")

# Search for test case files
for dir in "${directories[@]}"; do
    for pattern in "${patterns[@]}"; do
        # Files starting with pattern
        find $PWD -type f -path "*/*${dir}*/*" -name "${pattern}*" >> /tmp/all-tests.raw
        # Files with pattern as extension
        find $PWD -type f -path "*/*${dir}*/*" -name "*.${pattern}" >> /tmp/all-tests.raw
    done
done

# Also look for common test case patterns regardless of directory
find $PWD -type f -name "clusterfuzz-testcase-*" >> /tmp/all-tests.raw
find $PWD -type f -name "*-fuzzer-testcase-*" >> /tmp/all-tests.raw
find $PWD -type f -name "oom-*" >> /tmp/all-tests.raw
find $PWD -type f -name "timeout-*" >> /tmp/all-tests.raw
find $PWD -type f -name "leak-*" >> /tmp/all-tests.raw

# Sort and remove duplicates
cat /tmp/all-tests.raw | sort -u > /tmp/all-tests

# Remove source code files
# C/C++ files
sed -i '/\.c$/d' /tmp/all-tests
sed -i '/\.cpp$/d' /tmp/all-tests
sed -i '/\.cc$/d' /tmp/all-tests
sed -i '/\.cxx$/d' /tmp/all-tests
sed -i '/\.c++$/d' /tmp/all-tests
sed -i '/\.h$/d' /tmp/all-tests
sed -i '/\.hpp$/d' /tmp/all-tests
sed -i '/\.hh$/d' /tmp/all-tests
sed -i '/\.hxx$/d' /tmp/all-tests
sed -i '/\.h++$/d' /tmp/all-tests

# Other programming languages
sed -i '/\.java$/d' /tmp/all-tests
sed -i '/\.py$/d' /tmp/all-tests
sed -i '/\.js$/d' /tmp/all-tests
sed -i '/\.ts$/d' /tmp/all-tests
sed -i '/\.go$/d' /tmp/all-tests
sed -i '/\.rs$/d' /tmp/all-tests
sed -i '/\.cs$/d' /tmp/all-tests
sed -i '/\.rb$/d' /tmp/all-tests
sed -i '/\.php$/d' /tmp/all-tests
sed -i '/\.swift$/d' /tmp/all-tests
sed -i '/\.m$/d' /tmp/all-tests
sed -i '/\.mm$/d' /tmp/all-tests
sed -i '/\.kt$/d' /tmp/all-tests
sed -i '/\.scala$/d' /tmp/all-tests
sed -i '/\.pl$/d' /tmp/all-tests
sed -i '/\.lua$/d' /tmp/all-tests
sed -i '/\.r$/d' /tmp/all-tests
sed -i '/\.R$/d' /tmp/all-tests

# Shell scripts
sed -i '/\.sh$/d' /tmp/all-tests
sed -i '/\.bash$/d' /tmp/all-tests
sed -i '/\.zsh$/d' /tmp/all-tests
sed -i '/\.fish$/d' /tmp/all-tests
sed -i '/\.ksh$/d' /tmp/all-tests

# Schema and interface definition files
sed -i '/\.proto$/d' /tmp/all-tests
sed -i '/\.thrift$/d' /tmp/all-tests
sed -i '/\.avsc$/d' /tmp/all-tests
sed -i '/\.idl$/d' /tmp/all-tests
sed -i '/\.fbs$/d' /tmp/all-tests

# Build and config files
sed -i '/Makefile$/d' /tmp/all-tests
sed -i '/makefile$/d' /tmp/all-tests
sed -i '/CMakeLists\.txt$/d' /tmp/all-tests
sed -i '/\.cmake$/d' /tmp/all-tests
sed -i '/\.mk$/d' /tmp/all-tests
sed -i '/\.pro$/d' /tmp/all-tests
sed -i '/\.gradle$/d' /tmp/all-tests
sed -i '/\.sln$/d' /tmp/all-tests
sed -i '/\.vcxproj$/d' /tmp/all-tests

# Documentation and metadata
sed -i '/\.md$/d' /tmp/all-tests
sed -i '/\.yaml$/d' /tmp/all-tests
sed -i '/\.yml$/d' /tmp/all-tests
sed -i '/\.rst$/d' /tmp/all-tests
sed -i '/\.txt$/d' /tmp/all-tests
sed -i '/\.json$/d' /tmp/all-tests
sed -i '/\.xml$/d' /tmp/all-tests
sed -i '/\.toml$/d' /tmp/all-tests
sed -i '/\.ini$/d' /tmp/all-tests
sed -i '/\.cfg$/d' /tmp/all-tests
sed -i '/\.conf$/d' /tmp/all-tests

# Test results and diffs
sed -i '/expected\.txt$/d' /tmp/all-tests
sed -i '/\.expected$/d' /tmp/all-tests
sed -i '/\.summary$/d' /tmp/all-tests
sed -i '/\.diff$/d' /tmp/all-tests
sed -i '/\/patches\/$/d' /tmp/all-tests
sed -i '/\.patch$/d' /tmp/all-tests
sed -i '/\.result$/d' /tmp/all-tests
sed -i '/\.baseline$/d' /tmp/all-tests
sed -i '/\.baseline-jsc$/d' /tmp/all-tests
sed -i '/\.scores$/d' /tmp/all-tests
sed -i '/\.dot$/d' /tmp/all-tests
sed -i '/\.exp$/d' /tmp/all-tests
sed -i '/\.err$/d' /tmp/all-tests
sed -i '/\.out$/d' /tmp/all-tests
sed -i '/\.log$/d' /tmp/all-tests

# Object files and binaries
sed -i '/\.o$/d' /tmp/all-tests
sed -i '/\.obj$/d' /tmp/all-tests
sed -i '/\.so$/d' /tmp/all-tests
sed -i '/\.dll$/d' /tmp/all-tests
sed -i '/\.dylib$/d' /tmp/all-tests
sed -i '/\.a$/d' /tmp/all-tests
sed -i '/\.lib$/d' /tmp/all-tests
sed -i '/\.exe$/d' /tmp/all-tests
sed -i '/\.elf$/d' /tmp/all-tests

# Assembly files
sed -i '/\.asm$/d' /tmp/all-tests
sed -i '/\.s$/d' /tmp/all-tests
sed -i '/\.S$/d' /tmp/all-tests

# Archives (unless they're test inputs)
sed -i '/\.tar$/d' /tmp/all-tests
sed -i '/\.gz$/d' /tmp/all-tests
sed -i '/\.zip$/d' /tmp/all-tests
sed -i '/\.bz2$/d' /tmp/all-tests
sed -i '/\.xz$/d' /tmp/all-tests
sed -i '/\.7z$/d' /tmp/all-tests
sed -i '/\.rar$/d' /tmp/all-tests

# Database files
sed -i '/\.db$/d' /tmp/all-tests
sed -i '/\.sqlite$/d' /tmp/all-tests
sed -i '/\.sql$/d' /tmp/all-tests

# Merge results
cat /tmp/all-crashes /tmp/all-tests | sort -u