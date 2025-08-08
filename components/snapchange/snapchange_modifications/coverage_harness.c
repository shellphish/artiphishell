#define _GNU_SOURCE
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/types.h>
#include <sanitizer/coverage_interface.h>

#define KCOV_INIT_TRACE                     _IOR('c', 1, unsigned long)
#define KCOV_ENABLE                         _IO('c', 100)
#define KCOV_DISABLE                        _IO('c', 101)
#define COVER_SIZE                          (64<<13)

#define KCOV_TRACE_PC  0
#define KCOV_TRACE_CMP 1

unsigned long *trace;
unsigned long *edge_start, *edge_stop;
unsigned char *file_mmap;


void enable_kcov(void) {
    unsigned long *cover;

    // Use the syscall function to open the file /sys/kernel/debug/kcov
    int fd = syscall(SYS_open, "/sys/kernel/debug/kcov", O_RDWR);
    if (fd == -1) {
        fputs("Could not open /sys/kernel/debug/kcov", stderr);
        exit(1);
    }
    if (ioctl(fd, KCOV_INIT_TRACE, COVER_SIZE))
        perror("ioctl"), exit(1);
    cover = (unsigned long*)mmap(NULL, COVER_SIZE * sizeof(unsigned long),
                                 PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if ((void*)cover == MAP_FAILED)
        perror("mmap"), exit(1);
    trace = cover;
    if (ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC))
        perror("ioctl"), exit(1);
    __atomic_store_n(&cover[0], 0, __ATOMIC_RELAXED);
}


void __sanitizer_cov_8bit_counters_init(char *start, char *end) {
    // [start,end) is the array of 8-bit counters created for the current DSO.
    // Capture this array in order to read/modify the counters.
    edge_start = (unsigned long *)start;
    edge_stop = (unsigned long *)end;
}


void take_snapshot (unsigned char *data_buffer){
    enable_kcov();
    // Print the buffer address
    printf("SNAPSHOT Data buffer: %p\n", data_buffer);
    // Print the KCOV buffer address
    printf("SNAPSHOT KCOV buffer: %p\n", trace);
    printf("SNAPSHOT EDGE buffer: %p-%p\n", edge_start, edge_stop);
    fflush(stdout);

    // Snapshot taken here
     __asm("int3; int3 ; vmcall");
}


__attribute__((constructor))
void premain(int argc, char **argv, char **envp) {
    if ( getenv("SNAPSHOT") != 0 ) {
        if (argc > 1) {
            argv[1] = strdup("/tmp/inp");
        }

        ////////////////////////////////////////
        file_mmap = mmap(0, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

        //  Fuzzer inserts input here
        take_snapshot(file_mmap);
    }
}

