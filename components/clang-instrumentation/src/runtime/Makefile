kleepath=~/griller/griller/klee/klee/include
CFLAGS += -Wno-implicit-function-declaration -ldl -Wno-format

# if KLEEPATH is not set, use the default path
ifndef KLEEPATH
KLEEPATH=$(kleepath)
endif

.PHONY: all normal_runtime

normal_runtime: 
	clang-18 -c -emit-llvm -g -O0 $(CFLAGS) -Xclang -disable-O0-optnone runtime.c -o runtime.bc

all: normal_runtime

clean:
	rm -f *.bc
	rm -f *.o
