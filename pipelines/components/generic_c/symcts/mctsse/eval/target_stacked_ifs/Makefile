.PHONY: all clean

# CC=clang
# CFLAGS= # -fsanitize-coverage=indirect-calls,trace-pc
CFLAGS=-O0
LDFLAGS=-L../../path_coverage_tracker/target/debug/ -lpath_coverage_tracker
CCPATH=$(shell realpath "$(CC)")
CCREPO=$(shell cd `dirname "$(CCPATH)"`; git rev-parse --show-toplevel; cd - > /dev/null)
CCNAME=$(shell basename "$(CCREPO)")
all: target_$(CCNAME) target_$(CCNAME)_pct
clean:
	@echo $(shell echo "CCPATH: $(CCPATH)")
	@echo $(shell echo "CCREPO: $(CCREPO)")
	@echo $(shell echo "CCNAME: $(CCNAME)")
	rm -f target.c target_*

target.c: generate.py
	python generate.py 1000

target_$(CCNAME): target.c ../util/libshm.h ../util/libshm.so
	$(CC) $(CFLAGS) -o $@ -g $< -L../util -lshm -lrt

target_$(CCNAME)_pct: target.c ../util/libshm.h
	$(CC) $(CFLAGS) -o $@ -g $< -L../../path_coverage_tracker/target/debug -lpath_coverage_tracker

# target_profiled.o: target.c ../util/libshm.h
# 	$(CC) $(CFLAGS) -c -g -o $@ $<

# target_profiled: target_profiled.o
# 	LD_LIBARRY_PATH=/usr/local/lib $(CC) -Wl,--no-as-needed,-lprofiler,--as-needed -g -o $@ $< -lrt $(LDFLAGS)
