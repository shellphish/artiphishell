.PHONY: all

HARNESS=./harness_crackaddr.c

AFLPP_DIR=../../../../../repos/AFLplusplus
AFLPP_UPSTREAM_DIR=../../../../../repos/AFLplusplus_upstream
SYMCC_DIR=../../../../../repos/symcc
SYMCC_LIBS_DIR=../../../../../repos/symcc_libs
SYMCC_RUNTIME_DIR=../../../runtime/target/release/

CFLAGS_aflpp_driver=-I$(AFLPP_DIR)/include $(AFLPP_DIR)/utils/aflpp_driver/aflpp_driver.c
CFLAGS=-Wno-sign-compare -funroll-loops -unroll-count=16 -O1 -g
SANITIZER_CFLAGS=-fsanitize=undefined -fsanitize=array-bounds,bool,builtin,enum,float-divide-by-zero,function,integer-divide-by-zero,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unreachable,vla-bound,vptr -fno-sanitize-recover=all

ALL_TARGETS=harness_symcc harness_symcts harness_vanilla harness_vanilla_asan harness_symcts_afl++ harness_symcts_afl++.cmplog harness_afl++ harness_afl++.cmplog

all: $(ALL_TARGETS)
clean:
	rm -f $(ALL_TARGETS)

harness_symcc: ./$(HARNESS) Makefile
	$(SYMCC_DIR)/build_rust/symcc $(CFLAGS) $(CFLAGS_aflpp_driver) -fsanitize=undefined -fsanitize-trap=all -o $@ $< -L$(SYMCC_LIBS_DIR)/symcc_libc_preload/ $(LDFLAGS) -lm -l:libc_symcc_preload.a

harness_symcts: ./$(HARNESS)  Makefile
	SYMCC_RUNTIME_DIR=$(SYMCC_RUNTIME_DIR) $(SYMCC_DIR)/build_rust/symcc $(CFLAGS) $(CFLAGS_aflpp_driver) -fsanitize=undefined -fsanitize-trap=all -o $@ $< -L$(SYMCC_LIBS_DIR)/symcc_libc_preload/ $(LDFLAGS) -lm -l:libc_symcc_preload.a

harness_vanilla: $(HARNESS) Makefile
	clang-15 $(CFLAGS) $(CFLAGS_aflpp_driver) -o $@ $< $(LDFLAGS) -lm

harness_vanilla_asan: $(HARNESS) Makefile
	clang-15 $(SANITIZER_CFLAGS) $(CFLAGS) $(CFLAGS_aflpp_driver) -o $@ $< $(LDFLAGS) -lm

harness_symcts_afl++: $(HARNESS) Makefile
	$(AFLPP_DIR)/afl-clang-fast $(SANITIZER_CFLAGS) $(CFLAGS) $(AFLPP_DIR)/libAFLDriver.a -o $@ $< $(LDFLAGS) -lm

harness_symcts_afl++.cmplog: $(HARNESS) Makefile
	AFL_LLVM_CMPLOG=1 $(AFLPP_DIR)/afl-clang-fast $(CFLAGS) $(AFLPP_DIR)/libAFLDriver.a -o $@ $< $(LDFLAGS) -lm


harness_afl++: $(HARNESS) Makefile
	$(AFLPP_UPSTREAM_DIR)/afl-clang-fast $(SANITIZER_CFLAGS) $(CFLAGS) $(AFLPP_UPSTREAM_DIR)/libAFLDriver.a -o $@ $< $(LDFLAGS) -lm

harness_afl++.cmplog: $(HARNESS) Makefile
	AFL_LLVM_CMPLOG=1 $(AFLPP_UPSTREAM_DIR)/afl-clang-fast $(CFLAGS) $(AFLPP_UPSTREAM_DIR)/libAFLDriver.a -o $@ $< $(LDFLAGS) -lm
