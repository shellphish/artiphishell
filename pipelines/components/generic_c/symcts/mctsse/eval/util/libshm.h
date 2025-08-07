#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#define NUM_INTS (0x10000)
#define SHARED_SIZE (NUM_INTS * 8)
volatile int* numerical_coverage;

void unlink_shm(char* name);
void* create_shm(char* name, size_t size, int readonly);
void* map_shared_mem(char* name, size_t size, int readonly);
void report_numerical_coverage(void* shared, int number);