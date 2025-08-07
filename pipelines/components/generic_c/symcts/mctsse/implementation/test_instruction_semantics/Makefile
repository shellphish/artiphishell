
.PHONY: all
all: div_lib.so tester_fuzz_divb tester_fuzz_divw tester_fuzz_divl tester_fuzz_divq tester_fuzz_idivb tester_fuzz_idivw tester_fuzz_idivl tester_fuzz_idivq

div_lib.so: div_lib.c div_lib.h
	gcc -shared -o $@ $< -lm

# tester.c: gen_all_divb_cases.py div_lib.so
# 	python gen_divb_cases.py divb

# tester_idivb.c: gen_all_divb_cases.py div_lib.so
# 	python gen_divb_cases.py idivb

# tester: tester.c div_lib.c div_lib.h
# 	gcc -o $@ $^ -lm

tester_fuzz_divb.c: gen_fuzz_div_cases.py div_lib.so
	python gen_fuzz_div_cases.py divb 100

tester_fuzz_idivb.c: gen_fuzz_div_cases.py div_lib.so
	python gen_fuzz_div_cases.py idivb 100

tester_fuzz_divw.c: gen_fuzz_div_cases.py div_lib.so
	python gen_fuzz_div_cases.py divw 100

tester_fuzz_idivw.c: gen_fuzz_div_cases.py div_lib.so
	python gen_fuzz_div_cases.py idivw 100

tester_fuzz_divl.c: gen_fuzz_div_cases.py div_lib.so
	python gen_fuzz_div_cases.py divl 100

tester_fuzz_idivl.c: gen_fuzz_div_cases.py div_lib.so
	python gen_fuzz_div_cases.py idivl 100

tester_fuzz_divq.c: gen_fuzz_div_cases.py div_lib.so
	python gen_fuzz_div_cases.py divq 100

tester_fuzz_idivq.c: gen_fuzz_div_cases.py div_lib.so
	python gen_fuzz_div_cases.py idivq 100


tester_fuzz_divb: tester_fuzz_divb.c div_lib.c div_lib.h
	gcc -o $@ $^ -lm

tester_fuzz_idivb: tester_fuzz_idivb.c div_lib.c div_lib.h
	gcc -o $@ $^ -lm

tester_fuzz_divw: tester_fuzz_divw.c div_lib.c div_lib.h
	gcc -o $@ $^ -lm

tester_fuzz_idivw: tester_fuzz_idivw.c div_lib.c div_lib.h
	gcc -o $@ $^ -lm

tester_fuzz_divl: tester_fuzz_divl.c div_lib.c div_lib.h
	gcc -o $@ $^ -lm

tester_fuzz_idivl: tester_fuzz_idivl.c div_lib.c div_lib.h
	gcc -o $@ $^ -lm

tester_fuzz_divq: tester_fuzz_divq.c div_lib.c div_lib.h
	gcc -o $@ $^ -lm

tester_fuzz_idivq: tester_fuzz_idivq.c div_lib.c div_lib.h
	gcc -o $@ $^ -lm