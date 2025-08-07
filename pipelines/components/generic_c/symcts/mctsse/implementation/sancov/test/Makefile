CFLAGS=--std=c99
CFLAGS_PCGUARD=-fsanitize-coverage=pc-table,trace-pc-guard
CFLAGS_INLINE_8BIT=-fsanitize-coverage=pc-table,inline-8bit-counters
CFLAGS_INLINE_BOOL=-fsanitize-coverage=pc-table,inline-bool-flag
LDFLAGS=-L../target/debug/ -lsancov_instrumentation

.PHONY: all clean

all: test_pcguard test_inline_bool test_inline_8bit

test_pcguard.o: dummy.c
	clang $(CFLAGS) $(CFLAGS_PCGUARD) -c -o $@ $<

test_inline_bool.o: dummy.c
	clang $(CFLAGS) -fsanitize-coverage=pc-table,inline-bool-flag -c -o $@ $<

test_inline_8bit.o: dummy.c
	clang $(CFLAGS) -fsanitize-coverage=pc-table,inline-8bit-counters -c -o $@ $<

%: %.o
	clang $(LDFLAGS) -o $@ $<

clean:
	rm -f ./test_*
