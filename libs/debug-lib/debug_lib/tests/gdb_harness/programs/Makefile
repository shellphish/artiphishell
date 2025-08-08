# Find all directories containing a program.c file
DIRS = $(dir $(wildcard */program.c))
DEBUG_CCFLAGS = -g -O0
CCFLAGS = -O0

# Default target
all: $(addsuffix program,$(DIRS)) $(addsuffix program.debug,$(DIRS))

# Target to compile program in each directory
%/program: %/program.c
	cd $* && gcc $(CCFLAGS) program.c -o program -ggdb3

# Target to compile program.debug with debugging information
%/program.debug: %/program.c
	cd $* && gcc $(DEBUG_CCFLAGS) program.c -o program.debug -ggdb3

# Clean target to remove all binaries
clean:
	for dir in $(DIRS); do \
		rm -f $$dir/program $$dir/program.debug; \
	done

.PHONY: all clean
