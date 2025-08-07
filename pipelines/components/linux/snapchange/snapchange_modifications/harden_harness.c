#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/select.h>
#include <stdint.h>

// Function to simulate file descriptor operations
void perform_select(int* fds, int fd_count) {
    fd_set readfds;
    struct timeval tv;
    int max_fd = 0;

    FD_ZERO(&readfds);
    for (int i = 0; i < fd_count; i++) {
        if (fds[i] < 0 || fds[i] > FD_SETSIZE) {
            continue;
        }
        FD_SET(fds[i], &readfds);
        if (fds[i] > max_fd) {
            max_fd = fds[i];
        }
    }

    tv.tv_sec = 5;
    tv.tv_usec = 0;

    int retval = select(max_fd + 1, &readfds, NULL, NULL, &tv);

    if (retval == -1) {
        perror("select()");
    } else if (retval) {
        printf("Data is available now.\n");
    } else {
        printf("No data within five seconds.\n");
    }
}

/***
 * Blob begins with a 4 byte command count
 * [4-bytes command count]
 * Commands:
 *  0 - Add a file descriptor for select
 *      [4-bytes file descriptor]
 */
int harness(uint8_t *blob, uint32_t blob_size) {
    int index = 0;
    uint32_t command, command_count = 0;
    int fds[FD_SETSIZE];
    int fd_count = 0;

    if (blob == NULL || blob_size < 4) {
        return -1;
    }

    memcpy(&command_count, blob, 4);
    index += 4;

    printf("[INFO] Executing %d commands\n", command_count);

    for (int i = 0; i < command_count; i++) {
        if (blob_size - index < 4) {
            return -1;
        }

        memcpy(&command, blob + index, 4);
        index += 4;

        switch (command) {
            case 0:
                if (blob_size - index < 4) {
                    return -1;
                }
                if (fd_count >= FD_SETSIZE) {
                    printf("[ERROR] Too many file descriptors\n");
                    return -1;
                }

                memcpy(&fds[fd_count], blob + index, 4);
                fd_count++;
                index += 4;
                break;
            default:
                printf("[ERROR] Unknown command: %x\n", command);
                return -1;
        }
    }

    if (fd_count > 0) {
        perform_select(fds, fd_count);
    }

    printf("[INFO] Execution completed\n");
    return 0;
}

int main(int argc, char *argv[]) {
    uint8_t *blob = NULL;
    struct stat st;
    int fd;

    if (argc < 2) {
        printf("Need file\n");
        return -1;
    }

    if (stat(argv[1], &st) != 0) {
        printf("Failed to stat file\n");
        return -1;
    }

    fd = open(argv[1], O_RDONLY);

    if (fd < 0) {
        printf("[ERROR] Failed to open file\n");
        return -1;
    }

    blob = malloc(st.st_size);

    if (blob == NULL) {
        return 0;
    }

    read(fd, blob, st.st_size);
    close(fd);

    harness(blob, st.st_size);
    free(blob);

    return 0;
}
