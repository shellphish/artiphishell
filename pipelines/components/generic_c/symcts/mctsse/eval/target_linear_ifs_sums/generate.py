import sys
import random
from collections import namedtuple
template = '''
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../util/libshm.h"

int main(int argc, char* argv[]) {
    char* ident = getenv("COVERAGE_TRACKER_IDENT");
    if (!ident) {
        puts("Please set COVERAGE_TRACKER_IDENT to identify which process you stem from!\\n");
        exit(1);
    }
    void* coverage = map_shared_mem(ident, SHARED_SIZE, 0); // map shared memory as writable

    unsigned char buf[0x1000];
    int sums[0x1000];
    memset(buf, 0, 0x1000);
    memset(sums, 0, 0x1000*sizeof(int));
    int fd = 0;
    if (argc > 1) {
        fd = open(argv[1], O_RDONLY);
    }
    int num_chars = read(fd, buf, 0x1000);
    if (num_chars != 0x1000) {
        exit(0);
    }

    int sum = 0;
    for (int i = 0; i < num_chars; i ++) {
        sum += buf[i];
        sums[0xfff-i] = sum & 0xff;
    }

'''

rand = random.Random(1337)
for i in range(int(sys.argv[1])):
    alpha = rand.randint(0xf0, 255)
    lbrac,rbrac = '{}'
    template += f'    printf("Exiting with probability {alpha/256}/0x100 [{alpha/256:.5f}]!\\n");'
    template += f'    if(sums[0x{i:04x}] >= 0x{alpha:02x} ) {lbrac} report_numerical_coverage(coverage, {2*i}); {rbrac} else {lbrac} printf("Exited at step {i}!\\n"); report_numerical_coverage(coverage, {2*i+1}); exit(0); {rbrac}\n'
template += '}'

with open(f'target.c', 'w') as f:
    f.write(template)
