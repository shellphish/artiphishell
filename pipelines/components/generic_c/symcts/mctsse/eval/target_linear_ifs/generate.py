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
    memset(buf, 0, 0x1000);
    int fd = 0;
    if (argc > 1) {
        fd = open(argv[1], O_RDONLY);
    }
    int num_chars = read(fd, buf, 0x1000);

    if (num_chars != 0x1000) {
        exit(0);
    }

'''

rand = random.Random(1337)
for i in range(int(sys.argv[1])):
    alpha = 0xc0 #rand.randint(1, 255) 0xc0
    startpoint =  0x20 #rand.randint(0, 255-alpha)
    endpoint = startpoint + alpha
    assert 0 <= startpoint < endpoint <= 255
    lbrac,rbrac = '{}'
    template += f'    printf("Exiting with probability 0x{alpha:02x}/0x100 [{alpha/256:.5f}]!\\n");'
    template += f'    if(0x{startpoint:02x} <= buf[0x{i:04x}] && buf[0x{i:04x}] < 0x{endpoint:02x}) {lbrac} report_numerical_coverage(coverage, {2*i+1}); printf("Exited at step {i}!\\n"); exit(0); {rbrac} else {lbrac} report_numerical_coverage(coverage, {2*i}); {rbrac}\n'
    #template += f'    if(0x{startpoint:02x} <= buf[0x{i:04x}] && buf[0x{i:04x}] < 0x{endpoint:02x}) {lbrac} report_numerical_coverage(coverage, {2*i+1}); printf("Exited at step {i}!\\n"); exit(0); {rbrac}\n'
template += '}'

with open(f'target.c', 'w') as f:
    f.write(template)

