.PHONY: all

QSYMCC=../../../repos/symcc/build_qsym/symcc
QSYMPP=../../../repos/symcc/build_qsym/sym++
SYMCC=../../../repos/symcc/build_rust/symcc
SYMPP=../../../repos/symcc/build_rust/sym++
SYMAFLCC=../../../repos/symcc/build_rust/symcc-afl-clang
SYMAFLPP=../../../repos/symcc/build_rust/symcc-afl-clang++
AFLCC=../../../repos/AFLplusplus_upstream/afl-clang-fast
AFLPP=../../../repos/AFLplusplus_upstream/afl-clang-fast++
CC=clang-15
CPP=clang-15++

SYMCC_RUNTIME_DIR=../runtime/target/release

CFLAGS_aflpp_driver=-I../../../repos/AFLplusplus/include ../../../repos/AFLplusplus/utils/aflpp_driver/aflpp_driver.c
CFLAGS=-Wno-sign-compare -funroll-loops -unroll-count=16 -O1 -g
SANITIZER_CFLAGS=-fsanitize=undefined -fsanitize=array-bounds,bool,builtin,enum,float-divide-by-zero,function,integer-divide-by-zero,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unreachable,vla-bound,vptr -fno-sanitize-recover=all

ALL_TARGETS=target_symcts harness_symcc_coverage harness_symcc_sanitized harness_symcts_afl++ harness_symcts_afl++.cmplog harness_afl++ harness_afl++.cmplog

all: $(ALL_TARGETS)
clean:
	rm -f $(ALL_TARGETS)

target_symcc: ./harness_stb.c ./stb_image.h Makefile
	$(QSYMCC) $(CFLAGS) $(CFLAGS_aflpp_driver) -fsanitize=undefined -fsanitize-trap=all -o $@ $< -L../../../repos/symcc_libc_preload/ $(LDFLAGS) -lm -l:libc_symcc_preload.a

target_symcts: ./harness_stb.c ./stb_image.h Makefile
	SYMCC_RUNTIME_DIR=$(SYMCC_RUNTIME_DIR) $(SYMCC) $(CFLAGS) $(CFLAGS_aflpp_driver) -fsanitize=undefined -fsanitize-trap=all -o $@ $< -L../../../repos/symcc_libc_preload/ $(LDFLAGS) -lm -l:libc_symcc_preload.a

harness_symcc_coverage: harness_stb.c Makefile stb_image.h
	$(CC) $(CFLAGS) $(CFLAGS_aflpp_driver) -o $@ $< $(LDFLAGS) -lm

harness_symcc_sanitized: harness_stb.c Makefile stb_image.h
	$(CC) $(SANITIZER_CFLAGS) $(CFLAGS) $(CFLAGS_aflpp_driver) -o $@ $< $(LDFLAGS) -lm

harness_symcts_afl++: harness_stb.c Makefile stb_image.h
	$(SYMAFLCC) $(SANITIZER_CFLAGS) $(CFLAGS) ../../../repos/AFLplusplus/libAFLDriver.a -o $@ $< $(LDFLAGS) -lm

harness_symcts_afl++.cmplog: harness_stb.c Makefile stb_image.h
	AFL_LLVM_CMPLOG=1 $(SYMAFLCC) $(CFLAGS) ../../../repos/AFLplusplus/libAFLDriver.a -o $@ $< $(LDFLAGS) -lm


harness_afl++: harness_stb.c Makefile stb_image.h
	$(AFLCC) $(SANITIZER_CFLAGS) $(CFLAGS) ../../../repos/AFLplusplus_upstream/libAFLDriver.a -o $@ $< $(LDFLAGS) -lm

harness_afl++.cmplog: harness_stb.c Makefile stb_image.h
	AFL_LLVM_CMPLOG=1 $(AFLCC) $(CFLAGS) ../../../repos/AFLplusplus_upstream/libAFLDriver.a -o $@ $< $(LDFLAGS) -lm
