# Makefile for static library providing default implementations of mocked functions

all: libwrapdefaults.a

clean:
	rm -f *.o *.a

libwrapdefaults.a: wrapdefaults.o
	ar rcs $@ $^

wrapdefaults.c: generate_wrapdefaults.py
	python3 generate_wrapdefaults.py > $@

%.o: %.c
	clang -Wall -Werror -c -o $@ $<
