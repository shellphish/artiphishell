#!/usr/bin/env bash
set -xe

if [ $# -lt 3 ]; then
    echo "Usage: $0 <full-path-to-executable> <out_file> <utils_dir>"  
    exit 0
fi


binary="$1"
out_file="$2"
utils_dir="$3"
echo -n > $out_file ## empty file, it's gonna be there at least


function filter(){
    grep -vE "(__sanitizer::|__sanitizer_internal|__sanitizer_cov|__sanitizer_weak|wrapped_qsort|__interception::|___interceptor_|__interceptor_|__cxa_guard|__asan::|__asan_|__lsan::|__lsan_|__ubsan::|__ubsan_|__msan::|__msan_|fuzzer::|__Fuzzer::chrono|std::__Fuzzer::|initializeValueProfRuntimeRecord|writeFileWithoutReturn|__llvm_profile_write_file|lprofSuspendSigKill|__cxxabiv|__cxx_|__cxa|__sanitizer_|__sancov|sancov\.|asan_thread_start|deregister_tm_clones|__do_global_dtors_aux|asan.module_dtor|include\/c++|compiler-rt|\"_init\"|\"_end\")"
}

echo -n > $out_file ## empty file, it's gonna be there at least

$utils_dir/dwarf_inlined_parser $binary 2>&1 | sort -u | grep -v 0x0000000000000000 > inlines.txt || (echo "Inlined parsing did not work, continuing with empty inlines.txt" && exit 0)
wc inlines.txt

# check on the size
n=$(wc -l < inlines.txt)
if [ $n -eq 0 -o $n -eq 1 ]; then
    echo "No inlines found in $binary"
    rm inlines.txt || true
    exit 0
fi

LLVM_SYMBOLIZER=$(find /out /usr /bin -type f -executable -name "llvm-symbolizer*" 2>/dev/null | head -n 1)

if [ -z "$LLVM_SYMBOLIZER" ]; then
    echo "llvm-symbolizer not found in /usr or /bin, not pre-filtering inlined functions"
    exit 0
else
    echo "Using llvm-symbolizer at: $LLVM_SYMBOLIZER"
fi

echo "Pre-filtering inlined functions using llvm-symbolizer at: $LLVM_SYMBOLIZER"
cat inlines.txt | "$LLVM_SYMBOLIZER" -e $1 --output-style=JSON | filter | cut -f1 -d"," | cut -f2 -d":" | sed 's/"//g'  > cleaned_inlines.txt || true

if [ ! -f cleaned_inlines.txt -o ! -s cleaned_inlines.txt ]; then
    echo "No inlines found after pre-filtering with llvm-symbolizer"
    rm cleaned_inlines.txt || true
    exit 0
fi

mv cleaned_inlines.txt inlines.txt
wc -l inlines.txt


mv inlines.txt $out_file

echo "Inlines written to $out_file, final len $(wc -l < $out_file), size $(du -h $out_file | cut -f1)"