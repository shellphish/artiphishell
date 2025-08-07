// Harness for CVE-2021-4154
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>
#include <errno.h>
#include <linux/netlink.h>
#include <stddef.h>
#include <linux/types.h>

#define __NR_fsconfig 431
#define __NR_fsopen 430
#define FSCONFIG_SET_FD 5

int g_mtrrfd;

int fdtable[16] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};


int get_fd(uint8_t *blob) {
    unsigned int fd_index;

    memcpy(&fd_index, blob, 4);

    if (fd_index > 16) {
        printf("[ERROR] Attempted to get a fd beyond max number of fds\n");
        return -1;
    }

    int fd = fdtable[fd_index];
    return fd;
}

int fsopen_cmd(uint8_t *blob, int blob_size) {
    uint32_t fd_index = -1;
    int fd = -1;
    int fs_name_len;
    int index = 0;

    // Check if fd at index is already open
    memcpy(&fd_index, blob+index, 4);
    if (fd_index > 16) {
        printf("[ERROR] Attempted to get a fd beyond max number of fds\n");
        return -1;
    }
    fd = get_fd(blob+index);
    if (fd != -1) {
        return -1;
    }

    index += 4;

    fdtable[fd_index] = syscall(__NR_fsopen, "cgroup", 0ul);

    printf("fsopen: fd_table[%d] = %d\n", fd_index, fdtable[fd_index]);

    return index;
}

int close_cmd(uint8_t *blob) {
    uint32_t fd_index = -1;
    int fd = -1;
    int fs_name_len;
    int index = 0;

    // Check if fd at index is already closed
    memcpy(&fd_index, blob+index, 4);
    if (fd_index > 16) {
        printf("[ERROR] Attempted to get a fd beyond max number of fds\n");
        return -1;
    }
    fd = get_fd(blob+index);
    if (fd == -1) {
        return -1;
    }
    index += 4;

    fdtable[fd_index] = -1;

    printf("close: fd_table[%d]\n", fd_index);

    close(fd);
    return index;
}

int fsconfig_cmd(uint8_t *blob, uint32_t blob_size) {
    int fd = -1;
    int fs_name_len;
    uint32_t fsconfig_key_len;
    uint8_t *fsconfig_key;
    uint32_t cmd;
    int index = 0;


    // Check if fd is open
    fd = get_fd(blob + index);
    if (fd == -1) {
        return -1;
    }

    index += 4;

    memcpy(&cmd, blob+index, 4);
    index += 4;

    syscall(__NR_fsconfig, fd, cmd, "source", NULL, g_mtrrfd);

    printf("fsconfig: fsconfig(%d)\n", fd);

    return index;
}

int harness(uint8_t *blob, uint32_t blob_size)
{
    int index = 0;
    uint32_t command, command_count = 0;
    int res = 0;

    if ( blob == NULL ) {
        return -1;
    }

    g_mtrrfd = syscall(__NR_open, "/proc/mtrr", O_RDONLY);
    if (g_mtrrfd < 0) {
	    puts("open mtrr failed");
	    exit(1);
    }

    // A blob will at least be 4 bytes even if no packets are sent
    if ( blob_size < 4 ) {
        return -1;
    }

    memcpy(&command_count, blob, 4);
    index += 4;

    printf("[INFO] Executing %d commands\n", command_count);

    for ( int i = 0; i < command_count; i++) {
        if ( blob_size - index < 4 ) {
            return -1;
        }

        memcpy(&command, blob + index, 4);
        index += 4;

        switch ( command ) {
        case 0:
            res = fsopen_cmd(blob + index, blob_size-index);
            if (res == -1) {
                return -1;
            }
            index += res;
            break;
        case 1:
            res = close_cmd(blob + index);
            if (res == -1) {
                return -1;
            }
            index += res;
            break;
        case 2:
            res = fsconfig_cmd(blob + index, blob_size-index);
            if (res == -1) {
                return -1;
            }
            index += res;
            break;
        default:
            printf("[ERROR] Unknown command: %x\n", command);
            return -1;
        };

    }

    close(g_mtrrfd);

    return 0;
}

int main(int argc, char *argv[])
{
    uint8_t *blob = NULL;
    struct stat st;
    int fd;
    char filename[100] = "/sample_solve.bin";

    if (argc >= 2) {
	strncpy(filename, argv[1], 100);
        printf("Using file: %s\n", filename);
    }

    if ( stat(filename, &st) != 0) {
        printf("Failed to stat file\n");
        return -1;
    }

    fd = open(filename, O_RDONLY);

    if ( fd < 0 ) {
        printf("[ERROR] Failed to open file\n");
        return -1;
    }

    blob = mmap(0, st.st_size, PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);

    if ( blob == NULL ) {
        return 0;
    }

    read(fd, blob, st.st_size);

    close(fd);

    harness(blob, st.st_size);

    printf("exiting!\n");

    return 0;
}
