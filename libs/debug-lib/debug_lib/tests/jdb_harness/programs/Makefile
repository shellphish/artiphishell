# Find all directories containing a program.c file
DIRS = $(dir $(wildcard */Program.java))
DEBUG_CCFLAGS = -g
CCFLAGS =
.ONESHELL:

# Default target
all: $(addsuffix program.jar,$(DIRS)) $(addsuffix program.debug.jar,$(DIRS))

# Target to compile program in each directory
%/program.jar: SHELL:=/bin/bash
%/program.jar: %/Program.java
	pushd $*
	javac $(CCFLAGS) -d ./build *.java
	pushd build
	mkdir META-INF/
	echo "Main-Class: Program" > META-INF/MANIFEST.MF
	jar -cmf META-INF/MANIFEST.MF ../program.jar *
	popd
	rm -rf build
	popd

# Target to compile program.debug with debugging information
%/program.debug.jar: SHELL:=/bin/bash
%/program.debug.jar: %/Program.java
	pushd $*
	javac $(DEBUG_CCFLAGS) -d ./build *.java
	pushd build
	mkdir META-INF/
	echo "Main-Class: Program" > META-INF/MANIFEST.MF
	jar -cmf META-INF/MANIFEST.MF ../program.debug.jar *
	popd
	rm -rf build
	popd


# Clean target to remove all binaries
clean:
	for dir in $(DIRS); do \
		rm -f $$dir/program.jar $$dir/program.debug.jar; \
	done

.PHONY: all clean
