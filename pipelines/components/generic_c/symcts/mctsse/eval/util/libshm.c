#include "libshm.h"

__attribute__((noreturn)) void die(char* reason) {
    perror(reason);
    abort();
}

int _open_shm(char* name, int flags, int mode) {
    char* shm_name = NULL;
    if (!name || !*name)
        die("unlink_shm: An empty name is invalid!");
    int len = asprintf(&shm_name, "/%s", name);
    if (len < 2 || !shm_name)
        die("asprintf: could not create shm name");
        
    int fd = shm_open(shm_name, flags, mode);
    if (fd < 0)
        die("shm_open: Could not open shared memory!");
    free(shm_name);
    return fd;
}

void unlink_shm(char* name) {
    char* shm_name = NULL;
    if (!name || !*name)
        die("unlink_shm: An empty name is invalid!");
    int len = asprintf(&shm_name, "/%s", name);
    if (len < 2 || !shm_name) // it has to at least contain / + 1 char
        die("asprintf: could not create shm name");

    if (shm_unlink(shm_name) < 0) {
        die("shm_unlink: could not remove shared memory mapping");
    }
    free(shm_name);
}

void* create_shm(char* name, size_t size, int readonly) {
    int fd = _open_shm(name, O_CREAT|O_EXCL | (readonly ? O_RDONLY : O_RDWR), S_IRUSR | S_IWUSR);
    if (ftruncate(fd, size) < 0)
    {
        perror("ftruncate: could not set shared memory size");
        shm_unlink(name);
        abort();
    }
    void* addr = mmap(NULL, size, readonly ? PROT_READ : PROT_READ | PROT_WRITE, MAP_SHARED_VALIDATE, fd, 0);
    close(fd); // the man page says the fd can be closed after the mapping is created
    if (!addr)
        die("mmap: could not map new shared memory into address space");
    memset(addr, 0, size);
    return addr; 
}

void* map_shared_mem(char* name, size_t size, int readonly)
{
    int fd = _open_shm(name, readonly ? O_RDONLY : O_RDWR, 0);
    void* addr = mmap(NULL, size, readonly ? PROT_READ : PROT_READ | PROT_WRITE, MAP_SHARED_VALIDATE, fd, 0);
    close(fd); // the man page says the fd can be closed after the mapping is created
    if (!addr)
        die("mmap: could not map opened shared memory into address space");
    return addr; 
}

void report_numerical_coverage(void* shared, int number) {
    u_int64_t* t = (u_int64_t*)shared;
    u_int64_t old = t[number];
    while(!__sync_bool_compare_and_swap(&t[number], old, old+1)) {
        old = t[number];
    }
}