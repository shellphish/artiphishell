#include <sys/types.h>
#include <stdio.h>

typedef unsigned char uint8_t;

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    switch (data[0]) {
        case 0:
            printf("NULL byte\n");
            break;
        case 1:
            printf("SOH\n");
            exit(1);
            break;
        case 2:
            printf("STX\n");
            fprintf(stderr, "stderr\n");
            break;
        case 3:
            printf("ETX\n");
            fprintf(stdin, "stdin\n");
            break;
        case 4:
            printf("EOT\n");
            return 2;

        default:
            printf("other");
            break;
    }
}