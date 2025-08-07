#include <stdint.h>
#include <assert.h>
#include <sys/types.h>
#include <stdio.h>

extern int LLVMFuzzerInitialize(int *argc, char ***argv);
extern int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

// provide a weak definition of LLVMFuzzerInitialize
// so that we can link against a fuzzer that doesn't have it
__attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv) {
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        return -1;
    }
    LLVMFuzzerInitialize(&argc, &argv);

    char *file_path = argv[1];
    uint8_t *buf = malloc(0x10000);
    if (!buf) {
        return -1;
    }
    FILE *f = fopen(file_path, "rb");
    if (!f) {
        free(buf);
        return -1;
    }
    size_t size = fread(buf, 1, 0x10000, f);
    int result = LLVMFuzzerTestOneInput(buf, size);
    free(buf);
    return result;
}
