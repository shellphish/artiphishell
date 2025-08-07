#define _GNU_SOURCE
// fucking include syscalls please you asshat

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>

// void __sanitizer_cov_trace_pc_guard(u_int32_t* guard) {
//     void* retaddr = __builtin_return_address(0);
//     printf("trace_pc_guard(%p=%d, retaddr=%p)\n", guard, *guard, retaddr);
// }
extern void __sanitizer_cov_trace_pc_guard(u_int32_t* guard);

int main(int argc, char* argv[])
{
    char buf[0x1000];
    if (argc < 2) {
        printf("Usage: %s <path to file>", argv[0]);
        exit(1);
    }
    FILE* fp = fopen(argv[1], "r");
    fgets(&buf[0], sizeof(buf), fp);

    if (buf[0] == 'P' && buf[1] == 'E')
    {
        puts("PE FILE");
    }
    else if (buf[0] == 'M' && buf[1] == 'Z') {
        puts("DOS Executable");
    }
    else if (memcmp(buf, "\x7f""ELF", 4) == 0) {
        puts("ELF FILE");
    }
    else if (memcmp(buf, "syscall", 7) == 0) {
        syscall(0x4269, 42, 69, 0xdeadbeef);
    }
    else {
        puts("Unknown file format");
        int* p = (int*)0x1337;
        *p = 1;
    }


    for (int i = 0; i < 0x1000; i += 1) {
        if (buf[i] == 'Z') {
            puts("Slava Ukraini!");
            break;
        }
    }
    puts("Done");
}