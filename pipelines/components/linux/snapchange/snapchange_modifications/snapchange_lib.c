#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>

extern unsigned char *file_mmap;

int input_fd;
#define INPUT_FILENAME "/tmp/inp"

static int (*real_open)(const char *pathname, int flags, ...) = NULL;
static int (*real_stat)(const char *pathname, struct stat *buf) = NULL;
static int (*real_read)(int fd, void *buf, size_t sz) = NULL;
static int (*real_close)(int fd) = NULL;

// Our custom open function
int open(const char *pathname, int flags, ...) {
    if (!strcmp(pathname, INPUT_FILENAME)) {
        input_fd = 3;
        return input_fd;
    }
    if (!real_open) {
        real_open = dlsym(RTLD_NEXT, "open");
    }
    return real_open(pathname, flags);
}


// Our custom stat function
int stat(const char *pathname, struct stat *buf) {
    if (!strcmp(pathname, INPUT_FILENAME)) {
        buf->st_size = 0x1000;
        return 0;
    }
    if (!real_stat) {
        real_stat = dlsym(RTLD_NEXT, "stat");
    }
    return real_stat(pathname, buf);
}


// Our custom read function
int read(int fd, void *buf, size_t count) {
    if (fd == input_fd) {
        memcpy(buf, file_mmap, count);
        return count;
    }
    if (!real_read) {
        real_read = dlsym(RTLD_NEXT, "read");
    }
    return real_read(fd, buf, count);
}


// Our custom close function
int close(int fd) {
    if (fd == input_fd)
        return 0;
    if (!real_close) {
        real_close = dlsym(RTLD_NEXT, "close");
    }
    return real_close(fd);
}

// Our custom close function
int sleep(int secs) {
    return 0;
}
