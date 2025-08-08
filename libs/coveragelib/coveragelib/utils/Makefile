CC = gcc
ADDTIONAL_CFLAGS += -Wall -Wextra -std=gnu99 -g -I/usr/include/libdwarf
LDFLAGS = -L /usr/lib/x86_64-linux-gnu/ -ldwarf -lelf -lz -static

TARGET = dwarf_inlined_parser
SOURCE = dwarf_inlined_parser.c

.PHONY: all clean install-deps

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) $(ADDTIONAL_CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

test: $(TARGET)
	./$(TARGET) /bin/ls

help:
	@echo "Available targets:"
	@echo "  all           - Build the parser"
	@echo "  clean         - Remove built files"
	@echo "  install-deps  - Install dependencies (Ubuntu/Debian)"
	@echo "  install-deps-rhel - Install dependencies (RHEL/CentOS/Fedora)"
	@echo "  install-deps-macos - Install dependencies (macOS)"
	@echo "  test          - Test with /bin/ls"
	@echo "  help          - Show this help"