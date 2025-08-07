#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>

#ifdef __cplusplus
extern "C"
#endif

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
//extern int __llvm_profile_write_file(void);

// Catch abort signals and flush the perf data
// void libfuzzer_perf_signal_handler(int signo) {
    // __llvm_profile_write_file();
    // exit(0);
// }

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    //signal(SIGABRT, libfuzzer_perf_signal_handler);
    return 0;
}

void error(const char* s) {
    write(2, s, strlen(s));
    write(2, "\n", 1);
    exit(1);
}
char data[0x4000];

// weak declaration of LLVMFuzzerTestOneInput
__attribute__((weak)) int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    return 0;
}

// weak declaration of main
__attribute__((weak)) int main(int argc, char* argv[]) {

    LLVMFuzzerInitialize(&argc, &argv);

    size_t len = 0;
    if (argc > 1 && strcmp(argv[0], "-") == 0)
    {
    	len = read(0, data, sizeof(data));
    	if ( len <= 0 ) {
    	    error("Could not read input from stdin");
    	}
        LLVMFuzzerTestOneInput((const uint8_t*)data, len);
    }
    for (int i = 1; i < argc; i++) {
        int fd = open(argv[i], O_RDONLY);
	    if (fd < 1) {
               error("Could not open input file");
	    }
	    len = read(fd, data, sizeof(data));
	    if (len < 0) {
               error("Could not read input from file");
	    }
	    LLVMFuzzerTestOneInput((const uint8_t*)data, len);
    }
}