
#define _GNU_SOURCE

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/times.h>
#include <sys/wait.h>
#include <stdarg.h>
#include <grp.h>
#include <signal.h>
#include <pthread.h>
#include <crypt.h>

// getaddrinfo
#include <sys/socket.h>
#include <netdb.h>

// getpwuid
#include <pwd.h>

// writev
#include <sys/uio.h>

// poll
#include <poll.h>

// epoll_create
#include <sys/epoll.h>

// ioctl
#include <sys/ioctl.h>

// utime
#include <utime.h>

typedef void (*sighandler_t)(int);


__attribute__((weak)) void __real_exit(int status) {
    return exit(status);
}
__attribute__((weak)) void __wrap_exit(int status) {
    return __real_exit(status);
}

__attribute__((weak)) int __real_open(const char * path, int flags, mode_t mode) {
    return open(path, flags, mode);
}
__attribute__((weak)) int __wrap_open(const char * path, int flags, mode_t mode) {
    return __real_open(path, flags, mode);
}

__attribute__((weak)) int __real_close(int fd) {
    return close(fd);
}
__attribute__((weak)) int __wrap_close(int fd) {
    return __real_close(fd);
}

__attribute__((weak)) ssize_t __real_read(int fd, void * buf, size_t count) {
    return read(fd, buf, count);
}
__attribute__((weak)) ssize_t __wrap_read(int fd, void * buf, size_t count) {
    return __real_read(fd, buf, count);
}

__attribute__((weak)) ssize_t __real_write(int fd, const void * buf, size_t count) {
    return write(fd, buf, count);
}
__attribute__((weak)) ssize_t __wrap_write(int fd, const void * buf, size_t count) {
    return __real_write(fd, buf, count);
}

__attribute__((weak)) ssize_t __real_writev(int fd, const struct iovec * iov, int iovcnt) {
    return writev(fd, iov, iovcnt);
}
__attribute__((weak)) ssize_t __wrap_writev(int fd, const struct iovec * iov, int iovcnt) {
    return __real_writev(fd, iov, iovcnt);
}

__attribute__((weak)) off_t __real_lseek(int fd, off_t offset, int whence) {
    return lseek(fd, offset, whence);
}
__attribute__((weak)) off_t __wrap_lseek(int fd, off_t offset, int whence) {
    return __real_lseek(fd, offset, whence);
}

__attribute__((weak)) int __real_unlink(const char * path) {
    return unlink(path);
}
__attribute__((weak)) int __wrap_unlink(const char * path) {
    return __real_unlink(path);
}

__attribute__((weak)) int __real_fstat(int fd, struct stat * buf) {
    return fstat(fd, buf);
}
__attribute__((weak)) int __wrap_fstat(int fd, struct stat * buf) {
    return __real_fstat(fd, buf);
}

__attribute__((weak)) int __real_stat(const char * path, struct stat * buf) {
    return stat(path, buf);
}
__attribute__((weak)) int __wrap_stat(const char * path, struct stat * buf) {
    return __real_stat(path, buf);
}

__attribute__((weak)) int __real_mkdir(const char * path, mode_t mode) {
    return mkdir(path, mode);
}
__attribute__((weak)) int __wrap_mkdir(const char * path, mode_t mode) {
    return __real_mkdir(path, mode);
}

__attribute__((weak)) int __real_rmdir(const char * path) {
    return rmdir(path);
}
__attribute__((weak)) int __wrap_rmdir(const char * path) {
    return __real_rmdir(path);
}

__attribute__((weak)) DIR * __real_opendir(const char * name) {
    return opendir(name);
}
__attribute__((weak)) DIR * __wrap_opendir(const char * name) {
    return __real_opendir(name);
}

__attribute__((weak)) struct dirent * __real_readdir(DIR * dirp) {
    return readdir(dirp);
}
__attribute__((weak)) struct dirent * __wrap_readdir(DIR * dirp) {
    return __real_readdir(dirp);
}

__attribute__((weak)) int __real_closedir(DIR * dirp) {
    return closedir(dirp);
}
__attribute__((weak)) int __wrap_closedir(DIR * dirp) {
    return __real_closedir(dirp);
}

__attribute__((weak)) char * __real_getcwd(char * buf, size_t size) {
    return getcwd(buf, size);
}
__attribute__((weak)) char * __wrap_getcwd(char * buf, size_t size) {
    return __real_getcwd(buf, size);
}

__attribute__((weak)) int __real_chdir(const char * path) {
    return chdir(path);
}
__attribute__((weak)) int __wrap_chdir(const char * path) {
    return __real_chdir(path);
}

__attribute__((weak)) int __real_rename(const char * oldpath, const char * newpath) {
    return rename(oldpath, newpath);
}
__attribute__((weak)) int __wrap_rename(const char * oldpath, const char * newpath) {
    return __real_rename(oldpath, newpath);
}

__attribute__((weak)) pid_t __real_getpid() {
    return getpid();
}
__attribute__((weak)) pid_t __wrap_getpid() {
    return __real_getpid();
}

__attribute__((weak)) uid_t __real_getuid() {
    return getuid();
}
__attribute__((weak)) uid_t __wrap_getuid() {
    return __real_getuid();
}

__attribute__((weak)) uid_t __real_geteuid() {
    return geteuid();
}
__attribute__((weak)) uid_t __wrap_geteuid() {
    return __real_geteuid();
}

__attribute__((weak)) gid_t __real_getgid() {
    return getgid();
}
__attribute__((weak)) gid_t __wrap_getgid() {
    return __real_getgid();
}

__attribute__((weak)) gid_t __real_getegid() {
    return getegid();
}
__attribute__((weak)) gid_t __wrap_getegid() {
    return __real_getegid();
}

__attribute__((weak)) int __real_setuid(uid_t uid) {
    return setuid(uid);
}
__attribute__((weak)) int __wrap_setuid(uid_t uid) {
    return __real_setuid(uid);
}

__attribute__((weak)) int __real_setgid(gid_t gid) {
    return setgid(gid);
}
__attribute__((weak)) int __wrap_setgid(gid_t gid) {
    return __real_setgid(gid);
}

__attribute__((weak)) int __real_seteuid(uid_t uid) {
    return seteuid(uid);
}
__attribute__((weak)) int __wrap_seteuid(uid_t uid) {
    return __real_seteuid(uid);
}

__attribute__((weak)) int __real_setegid(gid_t gid) {
    return setegid(gid);
}
__attribute__((weak)) int __wrap_setegid(gid_t gid) {
    return __real_setegid(gid);
}

__attribute__((weak)) int __real_getgroups(int size, gid_t * list) {
    return getgroups(size, list);
}
__attribute__((weak)) int __wrap_getgroups(int size, gid_t * list) {
    return __real_getgroups(size, list);
}

__attribute__((weak)) int __real_setgroups(size_t size, const gid_t * list) {
    return setgroups(size, list);
}
__attribute__((weak)) int __wrap_setgroups(size_t size, const gid_t * list) {
    return __real_setgroups(size, list);
}

__attribute__((weak)) pid_t __real_getpgrp() {
    return getpgrp();
}
__attribute__((weak)) pid_t __wrap_getpgrp() {
    return __real_getpgrp();
}

__attribute__((weak)) int __real_setpgid(pid_t pid, pid_t pgid) {
    return setpgid(pid, pgid);
}
__attribute__((weak)) int __wrap_setpgid(pid_t pid, pid_t pgid) {
    return __real_setpgid(pid, pgid);
}

__attribute__((weak)) pid_t __real_getppid() {
    return getppid();
}
__attribute__((weak)) pid_t __wrap_getppid() {
    return __real_getppid();
}

__attribute__((weak)) pid_t __real_setsid() {
    return setsid();
}
__attribute__((weak)) pid_t __wrap_setsid() {
    return __real_setsid();
}

__attribute__((weak)) pid_t __real_getpgid(pid_t pid) {
    return getpgid(pid);
}
__attribute__((weak)) pid_t __wrap_getpgid(pid_t pid) {
    return __real_getpgid(pid);
}

__attribute__((weak)) char * __real_getlogin() {
    return getlogin();
}
__attribute__((weak)) char * __wrap_getlogin() {
    return __real_getlogin();
}

__attribute__((weak)) int __real_gethostname(char * name, size_t len) {
    return gethostname(name, len);
}
__attribute__((weak)) int __wrap_gethostname(char * name, size_t len) {
    return __real_gethostname(name, len);
}

__attribute__((weak)) int __real_sethostname(const char * name, size_t len) {
    return sethostname(name, len);
}
__attribute__((weak)) int __wrap_sethostname(const char * name, size_t len) {
    return __real_sethostname(name, len);
}

__attribute__((weak)) int __real_getdomainname(char * name, size_t len) {
    return getdomainname(name, len);
}
__attribute__((weak)) int __wrap_getdomainname(char * name, size_t len) {
    return __real_getdomainname(name, len);
}

__attribute__((weak)) int __real_setdomainname(const char * name, size_t len) {
    return setdomainname(name, len);
}
__attribute__((weak)) int __wrap_setdomainname(const char * name, size_t len) {
    return __real_setdomainname(name, len);
}

__attribute__((weak)) int __real_getrlimit(int resource, struct rlimit * rlp) {
    return getrlimit(resource, rlp);
}
__attribute__((weak)) int __wrap_getrlimit(int resource, struct rlimit * rlp) {
    return __real_getrlimit(resource, rlp);
}

__attribute__((weak)) int __real_setrlimit(int resource, const struct rlimit * rlp) {
    return setrlimit(resource, rlp);
}
__attribute__((weak)) int __wrap_setrlimit(int resource, const struct rlimit * rlp) {
    return __real_setrlimit(resource, rlp);
}

__attribute__((weak)) int __real_getrusage(int who, struct rusage * usage) {
    return getrusage(who, usage);
}
__attribute__((weak)) int __wrap_getrusage(int who, struct rusage * usage) {
    return __real_getrusage(who, usage);
}

__attribute__((weak)) clock_t __real_times(struct tms * buf) {
    return times(buf);
}
__attribute__((weak)) clock_t __wrap_times(struct tms * buf) {
    return __real_times(buf);
}

__attribute__((weak)) int __real_gettimeofday(struct timeval * tv, struct timezone * tz) {
    return gettimeofday(tv, tz);
}
__attribute__((weak)) int __wrap_gettimeofday(struct timeval * tv, struct timezone * tz) {
    return __real_gettimeofday(tv, tz);
}

__attribute__((weak)) int __real_settimeofday(const struct timeval * tv, const struct timezone * tz) {
    return settimeofday(tv, tz);
}
__attribute__((weak)) int __wrap_settimeofday(const struct timeval * tv, const struct timezone * tz) {
    return __real_settimeofday(tv, tz);
}

__attribute__((weak)) int __real_getitimer(int which, struct itimerval * value) {
    return getitimer(which, value);
}
__attribute__((weak)) int __wrap_getitimer(int which, struct itimerval * value) {
    return __real_getitimer(which, value);
}

__attribute__((weak)) int __real_setitimer(int which, const struct itimerval * value, struct itimerval * ovalue) {
    return setitimer(which, value, ovalue);
}
__attribute__((weak)) int __wrap_setitimer(int which, const struct itimerval * value, struct itimerval * ovalue) {
    return __real_setitimer(which, value, ovalue);
}

__attribute__((weak)) void __real_srand(unsigned int seed) {
    return srand(seed);
}
__attribute__((weak)) void __wrap_srand(unsigned int seed) {
    return __real_srand(seed);
}

__attribute__((weak)) int __real_rand() {
    return rand();
}
__attribute__((weak)) int __wrap_rand() {
    return __real_rand();
}

__attribute__((weak)) int __real_rand_r(unsigned int * seedp) {
    return rand_r(seedp);
}
__attribute__((weak)) int __wrap_rand_r(unsigned int * seedp) {
    return __real_rand_r(seedp);
}

__attribute__((weak)) void * __real_malloc(size_t size) {
    return malloc(size);
}
__attribute__((weak)) void * __wrap_malloc(size_t size) {
    return __real_malloc(size);
}

__attribute__((weak)) void * __real_calloc(size_t nmemb, size_t size) {
    return calloc(nmemb, size);
}
__attribute__((weak)) void * __wrap_calloc(size_t nmemb, size_t size) {
    return __real_calloc(nmemb, size);
}

__attribute__((weak)) void * __real_realloc(void * ptr, size_t size) {
    return realloc(ptr, size);
}
__attribute__((weak)) void * __wrap_realloc(void * ptr, size_t size) {
    return __real_realloc(ptr, size);
}

__attribute__((weak)) void __real_free(void * ptr) {
    return free(ptr);
}
__attribute__((weak)) void __wrap_free(void * ptr) {
    return __real_free(ptr);
}

__attribute__((weak)) void __real_abort() {
    return abort();
}
__attribute__((weak)) void __wrap_abort() {
    return __real_abort();
}

__attribute__((weak)) int __real_atexit(void (*func)(void)) {
    return atexit(func);
}
__attribute__((weak)) int __wrap_atexit(void (*func)(void)) {
    return __real_atexit(func);
}

__attribute__((weak)) int __real_system(const char * command) {
    return system(command);
}
__attribute__((weak)) int __wrap_system(const char * command) {
    return __real_system(command);
}

__attribute__((weak)) char * __real_getenv(const char * name) {
    return getenv(name);
}
__attribute__((weak)) char * __wrap_getenv(const char * name) {
    return __real_getenv(name);
}

__attribute__((weak)) int __real_putenv(char * string) {
    return putenv(string);
}
__attribute__((weak)) int __wrap_putenv(char * string) {
    return __real_putenv(string);
}

__attribute__((weak)) int __real_unsetenv(const char * name) {
    return unsetenv(name);
}
__attribute__((weak)) int __wrap_unsetenv(const char * name) {
    return __real_unsetenv(name);
}

__attribute__((weak)) int __real_clearenv() {
    return clearenv();
}
__attribute__((weak)) int __wrap_clearenv() {
    return __real_clearenv();
}

__attribute__((weak)) int __real_mkstemp(char * template) {
    return mkstemp(template);
}
__attribute__((weak)) int __wrap_mkstemp(char * template) {
    return __real_mkstemp(template);
}

__attribute__((weak)) char * __real_mkdtemp(char * template) {
    return mkdtemp(template);
}
__attribute__((weak)) char * __wrap_mkdtemp(char * template) {
    return __real_mkdtemp(template);
}

__attribute__((weak)) FILE * __real_tmpfile() {
    return tmpfile();
}
__attribute__((weak)) FILE * __wrap_tmpfile() {
    return __real_tmpfile();
}

__attribute__((weak)) char * __real_tmpnam(char * s) {
    return tmpnam(s);
}
__attribute__((weak)) char * __wrap_tmpnam(char * s) {
    return __real_tmpnam(s);
}

__attribute__((weak)) char * __real_tempnam(const char * dir, const char * pfx) {
    return tempnam(dir, pfx);
}
__attribute__((weak)) char * __wrap_tempnam(const char * dir, const char * pfx) {
    return __real_tempnam(dir, pfx);
}

__attribute__((weak)) int __real_fclose(FILE * stream) {
    return fclose(stream);
}
__attribute__((weak)) int __wrap_fclose(FILE * stream) {
    return __real_fclose(stream);
}

__attribute__((weak)) int __real_fflush(FILE * stream) {
    return fflush(stream);
}
__attribute__((weak)) int __wrap_fflush(FILE * stream) {
    return __real_fflush(stream);
}

__attribute__((weak)) FILE * __real_fopen(const char * path, const char * mode) {
    return fopen(path, mode);
}
__attribute__((weak)) FILE * __wrap_fopen(const char * path, const char * mode) {
    return __real_fopen(path, mode);
}

__attribute__((weak)) FILE * __real_freopen(const char * path, const char * mode, FILE * stream) {
    return freopen(path, mode, stream);
}
__attribute__((weak)) FILE * __wrap_freopen(const char * path, const char * mode, FILE * stream) {
    return __real_freopen(path, mode, stream);
}

__attribute__((weak)) FILE * __real_fdopen(int fd, const char * mode) {
    return fdopen(fd, mode);
}
__attribute__((weak)) FILE * __wrap_fdopen(int fd, const char * mode) {
    return __real_fdopen(fd, mode);
}

__attribute__((weak)) int __real_fgetc(FILE * stream) {
    return fgetc(stream);
}
__attribute__((weak)) int __wrap_fgetc(FILE * stream) {
    return __real_fgetc(stream);
}

__attribute__((weak)) int __real_getc(FILE * stream) {
    return getc(stream);
}
__attribute__((weak)) int __wrap_getc(FILE * stream) {
    return __real_getc(stream);
}

__attribute__((weak)) int __real_getchar() {
    return getchar();
}
__attribute__((weak)) int __wrap_getchar() {
    return __real_getchar();
}

__attribute__((weak)) int __real_fputc(int c, FILE * stream) {
    return fputc(c, stream);
}
__attribute__((weak)) int __wrap_fputc(int c, FILE * stream) {
    return __real_fputc(c, stream);
}

__attribute__((weak)) int __real_putc(int c, FILE * stream) {
    return putc(c, stream);
}
__attribute__((weak)) int __wrap_putc(int c, FILE * stream) {
    return __real_putc(c, stream);
}

__attribute__((weak)) int __real_putchar(int c) {
    return putchar(c);
}
__attribute__((weak)) int __wrap_putchar(int c) {
    return __real_putchar(c);
}

__attribute__((weak)) char * __real_fgets(char * s, int size, FILE * stream) {
    return fgets(s, size, stream);
}
__attribute__((weak)) char * __wrap_fgets(char * s, int size, FILE * stream) {
    return __real_fgets(s, size, stream);
}

__attribute__((weak)) int __real_fputs(const char * s, FILE * stream) {
    return fputs(s, stream);
}
__attribute__((weak)) int __wrap_fputs(const char * s, FILE * stream) {
    return __real_fputs(s, stream);
}

__attribute__((weak)) int __real_puts(const char * s) {
    return puts(s);
}
__attribute__((weak)) int __wrap_puts(const char * s) {
    return __real_puts(s);
}

__attribute__((weak)) int __real_feof(FILE * stream) {
    return feof(stream);
}
__attribute__((weak)) int __wrap_feof(FILE * stream) {
    return __real_feof(stream);
}

__attribute__((weak)) int __real_ferror(FILE * stream) {
    return ferror(stream);
}
__attribute__((weak)) int __wrap_ferror(FILE * stream) {
    return __real_ferror(stream);
}

__attribute__((weak)) void __real_clearerr(FILE * stream) {
    return clearerr(stream);
}
__attribute__((weak)) void __wrap_clearerr(FILE * stream) {
    return __real_clearerr(stream);
}

__attribute__((weak)) int __real_fileno(FILE * stream) {
    return fileno(stream);
}
__attribute__((weak)) int __wrap_fileno(FILE * stream) {
    return __real_fileno(stream);
}

__attribute__((weak)) void __real_perror(const char * s) {
    return perror(s);
}
__attribute__((weak)) void __wrap_perror(const char * s) {
    return __real_perror(s);
}

__attribute__((weak)) int __real_fseek(FILE * stream, long offset, int whence) {
    return fseek(stream, offset, whence);
}
__attribute__((weak)) int __wrap_fseek(FILE * stream, long offset, int whence) {
    return __real_fseek(stream, offset, whence);
}

__attribute__((weak)) long __real_ftell(FILE * stream) {
    return ftell(stream);
}
__attribute__((weak)) long __wrap_ftell(FILE * stream) {
    return __real_ftell(stream);
}

__attribute__((weak)) void __real_rewind(FILE * stream) {
    return rewind(stream);
}
__attribute__((weak)) void __wrap_rewind(FILE * stream) {
    return __real_rewind(stream);
}

__attribute__((weak)) size_t __real_fread(void * ptr, size_t size, size_t nmemb, FILE * stream) {
    return fread(ptr, size, nmemb, stream);
}
__attribute__((weak)) size_t __wrap_fread(void * ptr, size_t size, size_t nmemb, FILE * stream) {
    return __real_fread(ptr, size, nmemb, stream);
}

__attribute__((weak)) size_t __real_fwrite(const void * ptr, size_t size, size_t nmemb, FILE * stream) {
    return fwrite(ptr, size, nmemb, stream);
}
__attribute__((weak)) size_t __wrap_fwrite(const void * ptr, size_t size, size_t nmemb, FILE * stream) {
    return __real_fwrite(ptr, size, nmemb, stream);
}

__attribute__((weak)) int __real_fgetpos(FILE * stream, fpos_t * pos) {
    return fgetpos(stream, pos);
}
__attribute__((weak)) int __wrap_fgetpos(FILE * stream, fpos_t * pos) {
    return __real_fgetpos(stream, pos);
}

__attribute__((weak)) int __real_fsetpos(FILE * stream, const fpos_t * pos) {
    return fsetpos(stream, pos);
}
__attribute__((weak)) int __wrap_fsetpos(FILE * stream, const fpos_t * pos) {
    return __real_fsetpos(stream, pos);
}

__attribute__((weak)) int __real_pipe(int * pipefd) {
    return pipe(pipefd);
}
__attribute__((weak)) int __wrap_pipe(int * pipefd) {
    return __real_pipe(pipefd);
}

__attribute__((weak)) int __real_dup(int oldfd) {
    return dup(oldfd);
}
__attribute__((weak)) int __wrap_dup(int oldfd) {
    return __real_dup(oldfd);
}

__attribute__((weak)) int __real_dup2(int oldfd, int newfd) {
    return dup2(oldfd, newfd);
}
__attribute__((weak)) int __wrap_dup2(int oldfd, int newfd) {
    return __real_dup2(oldfd, newfd);
}

__attribute__((weak)) pid_t __real_fork() {
    return fork();
}
__attribute__((weak)) pid_t __wrap_fork() {
    return __real_fork();
}

__attribute__((weak)) pid_t __real_vfork() {
    return vfork();
}
__attribute__((weak)) pid_t __wrap_vfork() {
    return __real_vfork();
}

__attribute__((weak)) pid_t __real_wait(int * status) {
    return wait(status);
}
__attribute__((weak)) pid_t __wrap_wait(int * status) {
    return __real_wait(status);
}

__attribute__((weak)) pid_t __real_waitpid(pid_t pid, int * status, int options) {
    return waitpid(pid, status, options);
}
__attribute__((weak)) pid_t __wrap_waitpid(pid_t pid, int * status, int options) {
    return __real_waitpid(pid, status, options);
}

__attribute__((weak)) int __real_execv(const char * path, char *const * argv) {
    return execv(path, argv);
}
__attribute__((weak)) int __wrap_execv(const char * path, char *const * argv) {
    return __real_execv(path, argv);
}

__attribute__((weak)) int __real_execve(const char * path, char *const * argv, char *const * envp) {
    return execve(path, argv, envp);
}
__attribute__((weak)) int __wrap_execve(const char * path, char *const * argv, char *const * envp) {
    return __real_execve(path, argv, envp);
}

__attribute__((weak)) int __real_execvp(const char * file, char *const * argv) {
    return execvp(file, argv);
}
__attribute__((weak)) int __wrap_execvp(const char * file, char *const * argv) {
    return __real_execvp(file, argv);
}

__attribute__((weak)) FILE * __real_popen(const char * command, const char * type) {
    return popen(command, type);
}
__attribute__((weak)) FILE * __wrap_popen(const char * command, const char * type) {
    return __real_popen(command, type);
}

__attribute__((weak)) int __real_pclose(FILE * stream) {
    return pclose(stream);
}
__attribute__((weak)) int __wrap_pclose(FILE * stream) {
    return __real_pclose(stream);
}

__attribute__((weak)) sighandler_t __real_signal(int signum, sighandler_t handler) {
    return signal(signum, handler);
}
__attribute__((weak)) sighandler_t __wrap_signal(int signum, sighandler_t handler) {
    return __real_signal(signum, handler);
}

__attribute__((weak)) int __real_raise(int signum) {
    return raise(signum);
}
__attribute__((weak)) int __wrap_raise(int signum) {
    return __real_raise(signum);
}

__attribute__((weak)) int __real_kill(pid_t pid, int signum) {
    return kill(pid, signum);
}
__attribute__((weak)) int __wrap_kill(pid_t pid, int signum) {
    return __real_kill(pid, signum);
}

__attribute__((weak)) int __real_chmod(const char * path, mode_t mode) {
    return chmod(path, mode);
}
__attribute__((weak)) int __wrap_chmod(const char * path, mode_t mode) {
    return __real_chmod(path, mode);
}

__attribute__((weak)) int __real_chown(const char * path, uid_t owner, gid_t group) {
    return chown(path, owner, group);
}
__attribute__((weak)) int __wrap_chown(const char * path, uid_t owner, gid_t group) {
    return __real_chown(path, owner, group);
}

__attribute__((weak)) int __real_utime(const char * filename, const struct utimbuf * times) {
    return utime(filename, times);
}
__attribute__((weak)) int __wrap_utime(const char * filename, const struct utimbuf * times) {
    return __real_utime(filename, times);
}

__attribute__((weak)) int __real_utimes(const char * filename, const struct timeval * times) {
    return utimes(filename, times);
}
__attribute__((weak)) int __wrap_utimes(const char * filename, const struct timeval * times) {
    return __real_utimes(filename, times);
}

__attribute__((weak)) int __real_fchmod(int fd, mode_t mode) {
    return fchmod(fd, mode);
}
__attribute__((weak)) int __wrap_fchmod(int fd, mode_t mode) {
    return __real_fchmod(fd, mode);
}

__attribute__((weak)) int __real_fchown(int fd, uid_t owner, gid_t group) {
    return fchown(fd, owner, group);
}
__attribute__((weak)) int __wrap_fchown(int fd, uid_t owner, gid_t group) {
    return __real_fchown(fd, owner, group);
}

__attribute__((weak)) int __real_lchown(const char * path, uid_t owner, gid_t group) {
    return lchown(path, owner, group);
}
__attribute__((weak)) int __wrap_lchown(const char * path, uid_t owner, gid_t group) {
    return __real_lchown(path, owner, group);
}

__attribute__((weak)) int __real_link(const char * oldpath, const char * newpath) {
    return link(oldpath, newpath);
}
__attribute__((weak)) int __wrap_link(const char * oldpath, const char * newpath) {
    return __real_link(oldpath, newpath);
}

__attribute__((weak)) int __real_symlink(const char * oldpath, const char * newpath) {
    return symlink(oldpath, newpath);
}
__attribute__((weak)) int __wrap_symlink(const char * oldpath, const char * newpath) {
    return __real_symlink(oldpath, newpath);
}

__attribute__((weak)) ssize_t __real_readlink(const char * path, char * buf, size_t bufsiz) {
    return readlink(path, buf, bufsiz);
}
__attribute__((weak)) ssize_t __wrap_readlink(const char * path, char * buf, size_t bufsiz) {
    return __real_readlink(path, buf, bufsiz);
}

__attribute__((weak)) int __real_remove(const char * path) {
    return remove(path);
}
__attribute__((weak)) int __wrap_remove(const char * path) {
    return __real_remove(path);
}

__attribute__((weak)) char * __real_realpath(const char * path, char * resolved_path) {
    return realpath(path, resolved_path);
}
__attribute__((weak)) char * __wrap_realpath(const char * path, char * resolved_path) {
    return __real_realpath(path, resolved_path);
}

__attribute__((weak)) int __real_lstat(const char * path, struct stat * buf) {
    return lstat(path, buf);
}
__attribute__((weak)) int __wrap_lstat(const char * path, struct stat * buf) {
    return __real_lstat(path, buf);
}

__attribute__((weak)) int __real_fstatat(int dirfd, const char * pathname, struct stat * buf, int flags) {
    return fstatat(dirfd, pathname, buf, flags);
}
__attribute__((weak)) int __wrap_fstatat(int dirfd, const char * pathname, struct stat * buf, int flags) {
    return __real_fstatat(dirfd, pathname, buf, flags);
}

__attribute__((weak)) int __real_access(const char * pathname, int mode) {
    return access(pathname, mode);
}
__attribute__((weak)) int __wrap_access(const char * pathname, int mode) {
    return __real_access(pathname, mode);
}

__attribute__((weak)) int __real_euidaccess(const char * pathname, int mode) {
    return euidaccess(pathname, mode);
}
__attribute__((weak)) int __wrap_euidaccess(const char * pathname, int mode) {
    return __real_euidaccess(pathname, mode);
}

__attribute__((weak)) int __real_faccessat(int dirfd, const char * pathname, int mode, int flags) {
    return faccessat(dirfd, pathname, mode, flags);
}
__attribute__((weak)) int __wrap_faccessat(int dirfd, const char * pathname, int mode, int flags) {
    return __real_faccessat(dirfd, pathname, mode, flags);
}

__attribute__((weak)) int __real_select(int nfds, fd_set * readfds, fd_set * writefds, fd_set * exceptfds, struct timeval * timeout) {
    return select(nfds, readfds, writefds, exceptfds, timeout);
}
__attribute__((weak)) int __wrap_select(int nfds, fd_set * readfds, fd_set * writefds, fd_set * exceptfds, struct timeval * timeout) {
    return __real_select(nfds, readfds, writefds, exceptfds, timeout);
}

__attribute__((weak)) int __real_poll(struct pollfd * fds, nfds_t nfds, int timeout) {
    return poll(fds, nfds, timeout);
}
__attribute__((weak)) int __wrap_poll(struct pollfd * fds, nfds_t nfds, int timeout) {
    return __real_poll(fds, nfds, timeout);
}

__attribute__((weak)) int __real_ppoll(struct pollfd * fds, nfds_t nfds, const struct timespec * tmo_p, const sigset_t * sigmask) {
    return ppoll(fds, nfds, tmo_p, sigmask);
}
__attribute__((weak)) int __wrap_ppoll(struct pollfd * fds, nfds_t nfds, const struct timespec * tmo_p, const sigset_t * sigmask) {
    return __real_ppoll(fds, nfds, tmo_p, sigmask);
}

__attribute__((weak)) int __real_epoll_create(int size) {
    return epoll_create(size);
}
__attribute__((weak)) int __wrap_epoll_create(int size) {
    return __real_epoll_create(size);
}

__attribute__((weak)) int __real_epoll_create1(int flags) {
    return epoll_create1(flags);
}
__attribute__((weak)) int __wrap_epoll_create1(int flags) {
    return __real_epoll_create1(flags);
}

__attribute__((weak)) int __real_epoll_ctl(int epfd, int op, int fd, struct epoll_event * event) {
    return epoll_ctl(epfd, op, fd, event);
}
__attribute__((weak)) int __wrap_epoll_ctl(int epfd, int op, int fd, struct epoll_event * event) {
    return __real_epoll_ctl(epfd, op, fd, event);
}

__attribute__((weak)) int __real_epoll_wait(int epfd, struct epoll_event * events, int maxevents, int timeout) {
    return epoll_wait(epfd, events, maxevents, timeout);
}
__attribute__((weak)) int __wrap_epoll_wait(int epfd, struct epoll_event * events, int maxevents, int timeout) {
    return __real_epoll_wait(epfd, events, maxevents, timeout);
}

__attribute__((weak)) int __real_epoll_pwait(int epfd, struct epoll_event * events, int maxevents, int timeout, const sigset_t * sigmask) {
    return epoll_pwait(epfd, events, maxevents, timeout, sigmask);
}
__attribute__((weak)) int __wrap_epoll_pwait(int epfd, struct epoll_event * events, int maxevents, int timeout, const sigset_t * sigmask) {
    return __real_epoll_pwait(epfd, events, maxevents, timeout, sigmask);
}

__attribute__((weak)) int __real_ioctl(int fd, unsigned long request, void * arg) {
    return ioctl(fd, request, arg);
}
__attribute__((weak)) int __wrap_ioctl(int fd, unsigned long request, void * arg) {
    return __real_ioctl(fd, request, arg);
}

__attribute__((weak)) int __real_fcntl(int fd, int cmd, void * arg) {
    return fcntl(fd, cmd, arg);
}
__attribute__((weak)) int __wrap_fcntl(int fd, int cmd, void * arg) {
    return __real_fcntl(fd, cmd, arg);
}

__attribute__((weak)) int __real_getsockopt(int sockfd, int level, int optname, void * optval, socklen_t * optlen) {
    return getsockopt(sockfd, level, optname, optval, optlen);
}
__attribute__((weak)) int __wrap_getsockopt(int sockfd, int level, int optname, void * optval, socklen_t * optlen) {
    return __real_getsockopt(sockfd, level, optname, optval, optlen);
}

__attribute__((weak)) int __real_setsockopt(int sockfd, int level, int optname, const void * optval, socklen_t optlen) {
    return setsockopt(sockfd, level, optname, optval, optlen);
}
__attribute__((weak)) int __wrap_setsockopt(int sockfd, int level, int optname, const void * optval, socklen_t optlen) {
    return __real_setsockopt(sockfd, level, optname, optval, optlen);
}

__attribute__((weak)) int __real_socket(int domain, int type, int protocol) {
    return socket(domain, type, protocol);
}
__attribute__((weak)) int __wrap_socket(int domain, int type, int protocol) {
    return __real_socket(domain, type, protocol);
}

__attribute__((weak)) int __real_socketpair(int domain, int type, int protocol, int * sv) {
    return socketpair(domain, type, protocol, sv);
}
__attribute__((weak)) int __wrap_socketpair(int domain, int type, int protocol, int * sv) {
    return __real_socketpair(domain, type, protocol, sv);
}

__attribute__((weak)) int __real_bind(int sockfd, const struct sockaddr * addr, socklen_t addrlen) {
    return bind(sockfd, addr, addrlen);
}
__attribute__((weak)) int __wrap_bind(int sockfd, const struct sockaddr * addr, socklen_t addrlen) {
    return __real_bind(sockfd, addr, addrlen);
}

__attribute__((weak)) int __real_listen(int sockfd, int backlog) {
    return listen(sockfd, backlog);
}
__attribute__((weak)) int __wrap_listen(int sockfd, int backlog) {
    return __real_listen(sockfd, backlog);
}

__attribute__((weak)) int __real_accept(int sockfd, struct sockaddr * addr, socklen_t * addrlen) {
    return accept(sockfd, addr, addrlen);
}
__attribute__((weak)) int __wrap_accept(int sockfd, struct sockaddr * addr, socklen_t * addrlen) {
    return __real_accept(sockfd, addr, addrlen);
}

__attribute__((weak)) int __real_connect(int sockfd, const struct sockaddr * addr, socklen_t addrlen) {
    return connect(sockfd, addr, addrlen);
}
__attribute__((weak)) int __wrap_connect(int sockfd, const struct sockaddr * addr, socklen_t addrlen) {
    return __real_connect(sockfd, addr, addrlen);
}

__attribute__((weak)) int __real_shutdown(int sockfd, int how) {
    return shutdown(sockfd, how);
}
__attribute__((weak)) int __wrap_shutdown(int sockfd, int how) {
    return __real_shutdown(sockfd, how);
}

__attribute__((weak)) ssize_t __real_send(int sockfd, const void * buf, size_t len, int flags) {
    return send(sockfd, buf, len, flags);
}
__attribute__((weak)) ssize_t __wrap_send(int sockfd, const void * buf, size_t len, int flags) {
    return __real_send(sockfd, buf, len, flags);
}

__attribute__((weak)) ssize_t __real_recv(int sockfd, void * buf, size_t len, int flags) {
    return recv(sockfd, buf, len, flags);
}
__attribute__((weak)) ssize_t __wrap_recv(int sockfd, void * buf, size_t len, int flags) {
    return __real_recv(sockfd, buf, len, flags);
}

__attribute__((weak)) ssize_t __real_sendto(int sockfd, const void * buf, size_t len, int flags, const struct sockaddr * dest_addr, socklen_t addrlen) {
    return sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}
__attribute__((weak)) ssize_t __wrap_sendto(int sockfd, const void * buf, size_t len, int flags, const struct sockaddr * dest_addr, socklen_t addrlen) {
    return __real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

__attribute__((weak)) ssize_t __real_recvfrom(int sockfd, void * buf, size_t len, int flags, struct sockaddr * src_addr, socklen_t * addrlen) {
    return recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}
__attribute__((weak)) ssize_t __wrap_recvfrom(int sockfd, void * buf, size_t len, int flags, struct sockaddr * src_addr, socklen_t * addrlen) {
    return __real_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}

__attribute__((weak)) int __real_getsockname(int sockfd, struct sockaddr * addr, socklen_t * addrlen) {
    return getsockname(sockfd, addr, addrlen);
}
__attribute__((weak)) int __wrap_getsockname(int sockfd, struct sockaddr * addr, socklen_t * addrlen) {
    return __real_getsockname(sockfd, addr, addrlen);
}

__attribute__((weak)) int __real_getpeername(int sockfd, struct sockaddr * addr, socklen_t * addrlen) {
    return getpeername(sockfd, addr, addrlen);
}
__attribute__((weak)) int __wrap_getpeername(int sockfd, struct sockaddr * addr, socklen_t * addrlen) {
    return __real_getpeername(sockfd, addr, addrlen);
}

__attribute__((weak)) ssize_t __real_sendmsg(int sockfd, const struct msghdr * msg, int flags) {
    return sendmsg(sockfd, msg, flags);
}
__attribute__((weak)) ssize_t __wrap_sendmsg(int sockfd, const struct msghdr * msg, int flags) {
    return __real_sendmsg(sockfd, msg, flags);
}

__attribute__((weak)) ssize_t __real_recvmsg(int sockfd, struct msghdr * msg, int flags) {
    return recvmsg(sockfd, msg, flags);
}
__attribute__((weak)) ssize_t __wrap_recvmsg(int sockfd, struct msghdr * msg, int flags) {
    return __real_recvmsg(sockfd, msg, flags);
}

__attribute__((weak)) int __real_pthread_create(pthread_t * thread, const pthread_attr_t * attr, void *(*start_routine)(void *), void * arg) {
    return pthread_create(thread, attr, start_routine, arg);
}
__attribute__((weak)) int __wrap_pthread_create(pthread_t * thread, const pthread_attr_t * attr, void *(*start_routine)(void *), void * arg) {
    return __real_pthread_create(thread, attr, start_routine, arg);
}

__attribute__((weak)) void __real_pthread_exit(void * value_ptr) {
    return pthread_exit(value_ptr);
}
__attribute__((weak)) void __wrap_pthread_exit(void * value_ptr) {
    return __real_pthread_exit(value_ptr);
}

__attribute__((weak)) int __real_pthread_join(pthread_t thread, void ** value_ptr) {
    return pthread_join(thread, value_ptr);
}
__attribute__((weak)) int __wrap_pthread_join(pthread_t thread, void ** value_ptr) {
    return __real_pthread_join(thread, value_ptr);
}

__attribute__((weak)) int __real_pthread_detach(pthread_t thread) {
    return pthread_detach(thread);
}
__attribute__((weak)) int __wrap_pthread_detach(pthread_t thread) {
    return __real_pthread_detach(thread);
}

__attribute__((weak)) pthread_t __real_pthread_self() {
    return pthread_self();
}
__attribute__((weak)) pthread_t __wrap_pthread_self() {
    return __real_pthread_self();
}

__attribute__((weak)) int __real_pthread_equal(pthread_t t1, pthread_t t2) {
    return pthread_equal(t1, t2);
}
__attribute__((weak)) int __wrap_pthread_equal(pthread_t t1, pthread_t t2) {
    return __real_pthread_equal(t1, t2);
}

__attribute__((weak)) int __real_pthread_cancel(pthread_t thread) {
    return pthread_cancel(thread);
}
__attribute__((weak)) int __wrap_pthread_cancel(pthread_t thread) {
    return __real_pthread_cancel(thread);
}

__attribute__((weak)) int __real_pthread_setcancelstate(int state, int * oldstate) {
    return pthread_setcancelstate(state, oldstate);
}
__attribute__((weak)) int __wrap_pthread_setcancelstate(int state, int * oldstate) {
    return __real_pthread_setcancelstate(state, oldstate);
}

__attribute__((weak)) int __real_pthread_setcanceltype(int type, int * oldtype) {
    return pthread_setcanceltype(type, oldtype);
}
__attribute__((weak)) int __wrap_pthread_setcanceltype(int type, int * oldtype) {
    return __real_pthread_setcanceltype(type, oldtype);
}

__attribute__((weak)) void __real_pthread_testcancel() {
    return pthread_testcancel();
}
__attribute__((weak)) void __wrap_pthread_testcancel() {
    return __real_pthread_testcancel();
}

__attribute__((weak)) int __real_pthread_attr_init(pthread_attr_t * attr) {
    return pthread_attr_init(attr);
}
__attribute__((weak)) int __wrap_pthread_attr_init(pthread_attr_t * attr) {
    return __real_pthread_attr_init(attr);
}

__attribute__((weak)) int __real_pthread_attr_destroy(pthread_attr_t * attr) {
    return pthread_attr_destroy(attr);
}
__attribute__((weak)) int __wrap_pthread_attr_destroy(pthread_attr_t * attr) {
    return __real_pthread_attr_destroy(attr);
}

__attribute__((weak)) int __real_pthread_attr_getdetachstate(const pthread_attr_t * attr, int * detachstate) {
    return pthread_attr_getdetachstate(attr, detachstate);
}
__attribute__((weak)) int __wrap_pthread_attr_getdetachstate(const pthread_attr_t * attr, int * detachstate) {
    return __real_pthread_attr_getdetachstate(attr, detachstate);
}

__attribute__((weak)) int __real_pthread_attr_setdetachstate(pthread_attr_t * attr, int detachstate) {
    return pthread_attr_setdetachstate(attr, detachstate);
}
__attribute__((weak)) int __wrap_pthread_attr_setdetachstate(pthread_attr_t * attr, int detachstate) {
    return __real_pthread_attr_setdetachstate(attr, detachstate);
}

__attribute__((weak)) int __real_pthread_attr_getstacksize(const pthread_attr_t * attr, size_t * stacksize) {
    return pthread_attr_getstacksize(attr, stacksize);
}
__attribute__((weak)) int __wrap_pthread_attr_getstacksize(const pthread_attr_t * attr, size_t * stacksize) {
    return __real_pthread_attr_getstacksize(attr, stacksize);
}

__attribute__((weak)) int __real_pthread_attr_setstacksize(pthread_attr_t * attr, size_t stacksize) {
    return pthread_attr_setstacksize(attr, stacksize);
}
__attribute__((weak)) int __wrap_pthread_attr_setstacksize(pthread_attr_t * attr, size_t stacksize) {
    return __real_pthread_attr_setstacksize(attr, stacksize);
}

__attribute__((weak)) int __real_pthread_attr_getguardsize(const pthread_attr_t * attr, size_t * guardsize) {
    return pthread_attr_getguardsize(attr, guardsize);
}
__attribute__((weak)) int __wrap_pthread_attr_getguardsize(const pthread_attr_t * attr, size_t * guardsize) {
    return __real_pthread_attr_getguardsize(attr, guardsize);
}

__attribute__((weak)) int __real_pthread_attr_setguardsize(pthread_attr_t * attr, size_t guardsize) {
    return pthread_attr_setguardsize(attr, guardsize);
}
__attribute__((weak)) int __wrap_pthread_attr_setguardsize(pthread_attr_t * attr, size_t guardsize) {
    return __real_pthread_attr_setguardsize(attr, guardsize);
}

__attribute__((weak)) int __real_pthread_attr_getschedparam(const pthread_attr_t * attr, struct sched_param * param) {
    return pthread_attr_getschedparam(attr, param);
}
__attribute__((weak)) int __wrap_pthread_attr_getschedparam(const pthread_attr_t * attr, struct sched_param * param) {
    return __real_pthread_attr_getschedparam(attr, param);
}

__attribute__((weak)) int __real_pthread_attr_setschedparam(pthread_attr_t * attr, const struct sched_param * param) {
    return pthread_attr_setschedparam(attr, param);
}
__attribute__((weak)) int __wrap_pthread_attr_setschedparam(pthread_attr_t * attr, const struct sched_param * param) {
    return __real_pthread_attr_setschedparam(attr, param);
}

__attribute__((weak)) int __real_pthread_attr_getschedpolicy(const pthread_attr_t * attr, int * policy) {
    return pthread_attr_getschedpolicy(attr, policy);
}
__attribute__((weak)) int __wrap_pthread_attr_getschedpolicy(const pthread_attr_t * attr, int * policy) {
    return __real_pthread_attr_getschedpolicy(attr, policy);
}

__attribute__((weak)) int __real_pthread_attr_setschedpolicy(pthread_attr_t * attr, int policy) {
    return pthread_attr_setschedpolicy(attr, policy);
}
__attribute__((weak)) int __wrap_pthread_attr_setschedpolicy(pthread_attr_t * attr, int policy) {
    return __real_pthread_attr_setschedpolicy(attr, policy);
}

__attribute__((weak)) int __real_pthread_attr_getinheritsched(const pthread_attr_t * attr, int * inheritsched) {
    return pthread_attr_getinheritsched(attr, inheritsched);
}
__attribute__((weak)) int __wrap_pthread_attr_getinheritsched(const pthread_attr_t * attr, int * inheritsched) {
    return __real_pthread_attr_getinheritsched(attr, inheritsched);
}

__attribute__((weak)) int __real_pthread_attr_setinheritsched(pthread_attr_t * attr, int inheritsched) {
    return pthread_attr_setinheritsched(attr, inheritsched);
}
__attribute__((weak)) int __wrap_pthread_attr_setinheritsched(pthread_attr_t * attr, int inheritsched) {
    return __real_pthread_attr_setinheritsched(attr, inheritsched);
}

__attribute__((weak)) int __real_pthread_attr_getscope(const pthread_attr_t * attr, int * scope) {
    return pthread_attr_getscope(attr, scope);
}
__attribute__((weak)) int __wrap_pthread_attr_getscope(const pthread_attr_t * attr, int * scope) {
    return __real_pthread_attr_getscope(attr, scope);
}

__attribute__((weak)) int __real_pthread_attr_setscope(pthread_attr_t * attr, int scope) {
    return pthread_attr_setscope(attr, scope);
}
__attribute__((weak)) int __wrap_pthread_attr_setscope(pthread_attr_t * attr, int scope) {
    return __real_pthread_attr_setscope(attr, scope);
}

__attribute__((weak)) int __real_pthread_attr_getstack(const pthread_attr_t * attr, void ** stackaddr, size_t * stacksize) {
    return pthread_attr_getstack(attr, stackaddr, stacksize);
}
__attribute__((weak)) int __wrap_pthread_attr_getstack(const pthread_attr_t * attr, void ** stackaddr, size_t * stacksize) {
    return __real_pthread_attr_getstack(attr, stackaddr, stacksize);
}

__attribute__((weak)) int __real_pthread_attr_setstack(pthread_attr_t * attr, void * stackaddr, size_t stacksize) {
    return pthread_attr_setstack(attr, stackaddr, stacksize);
}
__attribute__((weak)) int __wrap_pthread_attr_setstack(pthread_attr_t * attr, void * stackaddr, size_t stacksize) {
    return __real_pthread_attr_setstack(attr, stackaddr, stacksize);
}

__attribute__((weak)) int __real_pthread_getattr_default_np(pthread_attr_t * attr) {
    return pthread_getattr_default_np(attr);
}
__attribute__((weak)) int __wrap_pthread_getattr_default_np(pthread_attr_t * attr) {
    return __real_pthread_getattr_default_np(attr);
}

__attribute__((weak)) int __real_pthread_setattr_default_np(const pthread_attr_t * attr) {
    return pthread_setattr_default_np(attr);
}
__attribute__((weak)) int __wrap_pthread_setattr_default_np(const pthread_attr_t * attr) {
    return __real_pthread_setattr_default_np(attr);
}

__attribute__((weak)) int __real_pthread_mutex_init(pthread_mutex_t * mutex, const pthread_mutexattr_t * attr) {
    return pthread_mutex_init(mutex, attr);
}
__attribute__((weak)) int __wrap_pthread_mutex_init(pthread_mutex_t * mutex, const pthread_mutexattr_t * attr) {
    return __real_pthread_mutex_init(mutex, attr);
}

__attribute__((weak)) int __real_pthread_mutex_destroy(pthread_mutex_t * mutex) {
    return pthread_mutex_destroy(mutex);
}
__attribute__((weak)) int __wrap_pthread_mutex_destroy(pthread_mutex_t * mutex) {
    return __real_pthread_mutex_destroy(mutex);
}

__attribute__((weak)) int __real_pthread_mutex_lock(pthread_mutex_t * mutex) {
    return pthread_mutex_lock(mutex);
}
__attribute__((weak)) int __wrap_pthread_mutex_lock(pthread_mutex_t * mutex) {
    return __real_pthread_mutex_lock(mutex);
}

__attribute__((weak)) int __real_pthread_mutex_trylock(pthread_mutex_t * mutex) {
    return pthread_mutex_trylock(mutex);
}
__attribute__((weak)) int __wrap_pthread_mutex_trylock(pthread_mutex_t * mutex) {
    return __real_pthread_mutex_trylock(mutex);
}

__attribute__((weak)) int __real_pthread_mutex_unlock(pthread_mutex_t * mutex) {
    return pthread_mutex_unlock(mutex);
}
__attribute__((weak)) int __wrap_pthread_mutex_unlock(pthread_mutex_t * mutex) {
    return __real_pthread_mutex_unlock(mutex);
}

__attribute__((weak)) int __real_pthread_mutexattr_init(pthread_mutexattr_t * attr) {
    return pthread_mutexattr_init(attr);
}
__attribute__((weak)) int __wrap_pthread_mutexattr_init(pthread_mutexattr_t * attr) {
    return __real_pthread_mutexattr_init(attr);
}

__attribute__((weak)) int __real_pthread_mutexattr_destroy(pthread_mutexattr_t * attr) {
    return pthread_mutexattr_destroy(attr);
}
__attribute__((weak)) int __wrap_pthread_mutexattr_destroy(pthread_mutexattr_t * attr) {
    return __real_pthread_mutexattr_destroy(attr);
}

__attribute__((weak)) int __real_pthread_mutexattr_getpshared(const pthread_mutexattr_t * attr, int * pshared) {
    return pthread_mutexattr_getpshared(attr, pshared);
}
__attribute__((weak)) int __wrap_pthread_mutexattr_getpshared(const pthread_mutexattr_t * attr, int * pshared) {
    return __real_pthread_mutexattr_getpshared(attr, pshared);
}

__attribute__((weak)) int __real_pthread_mutexattr_setpshared(pthread_mutexattr_t * attr, int pshared) {
    return pthread_mutexattr_setpshared(attr, pshared);
}
__attribute__((weak)) int __wrap_pthread_mutexattr_setpshared(pthread_mutexattr_t * attr, int pshared) {
    return __real_pthread_mutexattr_setpshared(attr, pshared);
}

__attribute__((weak)) int __real_pthread_mutexattr_gettype(const pthread_mutexattr_t * attr, int * type) {
    return pthread_mutexattr_gettype(attr, type);
}
__attribute__((weak)) int __wrap_pthread_mutexattr_gettype(const pthread_mutexattr_t * attr, int * type) {
    return __real_pthread_mutexattr_gettype(attr, type);
}

__attribute__((weak)) int __real_pthread_mutexattr_settype(pthread_mutexattr_t * attr, int type) {
    return pthread_mutexattr_settype(attr, type);
}
__attribute__((weak)) int __wrap_pthread_mutexattr_settype(pthread_mutexattr_t * attr, int type) {
    return __real_pthread_mutexattr_settype(attr, type);
}

__attribute__((weak)) int __real_pthread_mutexattr_getprotocol(const pthread_mutexattr_t * attr, int * protocol) {
    return pthread_mutexattr_getprotocol(attr, protocol);
}
__attribute__((weak)) int __wrap_pthread_mutexattr_getprotocol(const pthread_mutexattr_t * attr, int * protocol) {
    return __real_pthread_mutexattr_getprotocol(attr, protocol);
}

__attribute__((weak)) int __real_pthread_mutexattr_setprotocol(pthread_mutexattr_t * attr, int protocol) {
    return pthread_mutexattr_setprotocol(attr, protocol);
}
__attribute__((weak)) int __wrap_pthread_mutexattr_setprotocol(pthread_mutexattr_t * attr, int protocol) {
    return __real_pthread_mutexattr_setprotocol(attr, protocol);
}

__attribute__((weak)) int __real_pthread_mutexattr_getprioceiling(const pthread_mutexattr_t * attr, int * prioceiling) {
    return pthread_mutexattr_getprioceiling(attr, prioceiling);
}
__attribute__((weak)) int __wrap_pthread_mutexattr_getprioceiling(const pthread_mutexattr_t * attr, int * prioceiling) {
    return __real_pthread_mutexattr_getprioceiling(attr, prioceiling);
}

__attribute__((weak)) int __real_pthread_mutexattr_setprioceiling(pthread_mutexattr_t * attr, int prioceiling) {
    return pthread_mutexattr_setprioceiling(attr, prioceiling);
}
__attribute__((weak)) int __wrap_pthread_mutexattr_setprioceiling(pthread_mutexattr_t * attr, int prioceiling) {
    return __real_pthread_mutexattr_setprioceiling(attr, prioceiling);
}

__attribute__((weak)) int __real_pthread_cond_init(pthread_cond_t * cond, const pthread_condattr_t * attr) {
    return pthread_cond_init(cond, attr);
}
__attribute__((weak)) int __wrap_pthread_cond_init(pthread_cond_t * cond, const pthread_condattr_t * attr) {
    return __real_pthread_cond_init(cond, attr);
}

__attribute__((weak)) int __real_pthread_cond_destroy(pthread_cond_t * cond) {
    return pthread_cond_destroy(cond);
}
__attribute__((weak)) int __wrap_pthread_cond_destroy(pthread_cond_t * cond) {
    return __real_pthread_cond_destroy(cond);
}

__attribute__((weak)) int __real_pthread_cond_wait(pthread_cond_t * cond, pthread_mutex_t * mutex) {
    return pthread_cond_wait(cond, mutex);
}
__attribute__((weak)) int __wrap_pthread_cond_wait(pthread_cond_t * cond, pthread_mutex_t * mutex) {
    return __real_pthread_cond_wait(cond, mutex);
}

__attribute__((weak)) int __real_pthread_cond_timedwait(pthread_cond_t * cond, pthread_mutex_t * mutex, const struct timespec * abstime) {
    return pthread_cond_timedwait(cond, mutex, abstime);
}
__attribute__((weak)) int __wrap_pthread_cond_timedwait(pthread_cond_t * cond, pthread_mutex_t * mutex, const struct timespec * abstime) {
    return __real_pthread_cond_timedwait(cond, mutex, abstime);
}

__attribute__((weak)) int __real_pthread_cond_signal(pthread_cond_t * cond) {
    return pthread_cond_signal(cond);
}
__attribute__((weak)) int __wrap_pthread_cond_signal(pthread_cond_t * cond) {
    return __real_pthread_cond_signal(cond);
}

__attribute__((weak)) int __real_pthread_cond_broadcast(pthread_cond_t * cond) {
    return pthread_cond_broadcast(cond);
}
__attribute__((weak)) int __wrap_pthread_cond_broadcast(pthread_cond_t * cond) {
    return __real_pthread_cond_broadcast(cond);
}

__attribute__((weak)) int __real_pthread_condattr_init(pthread_condattr_t * attr) {
    return pthread_condattr_init(attr);
}
__attribute__((weak)) int __wrap_pthread_condattr_init(pthread_condattr_t * attr) {
    return __real_pthread_condattr_init(attr);
}

__attribute__((weak)) int __real_pthread_condattr_destroy(pthread_condattr_t * attr) {
    return pthread_condattr_destroy(attr);
}
__attribute__((weak)) int __wrap_pthread_condattr_destroy(pthread_condattr_t * attr) {
    return __real_pthread_condattr_destroy(attr);
}

__attribute__((weak)) int __real_pthread_condattr_getpshared(const pthread_condattr_t * attr, int * pshared) {
    return pthread_condattr_getpshared(attr, pshared);
}
__attribute__((weak)) int __wrap_pthread_condattr_getpshared(const pthread_condattr_t * attr, int * pshared) {
    return __real_pthread_condattr_getpshared(attr, pshared);
}

__attribute__((weak)) int __real_pthread_condattr_setpshared(pthread_condattr_t * attr, int pshared) {
    return pthread_condattr_setpshared(attr, pshared);
}
__attribute__((weak)) int __wrap_pthread_condattr_setpshared(pthread_condattr_t * attr, int pshared) {
    return __real_pthread_condattr_setpshared(attr, pshared);
}

__attribute__((weak)) int __real_pthread_condattr_getclock(const pthread_condattr_t * attr, clockid_t * clock) {
    return pthread_condattr_getclock(attr, clock);
}
__attribute__((weak)) int __wrap_pthread_condattr_getclock(const pthread_condattr_t * attr, clockid_t * clock) {
    return __real_pthread_condattr_getclock(attr, clock);
}

__attribute__((weak)) int __real_pthread_condattr_setclock(pthread_condattr_t * attr, clockid_t clock) {
    return pthread_condattr_setclock(attr, clock);
}
__attribute__((weak)) int __wrap_pthread_condattr_setclock(pthread_condattr_t * attr, clockid_t clock) {
    return __real_pthread_condattr_setclock(attr, clock);
}

__attribute__((weak)) int __real_pthread_key_create(pthread_key_t * key, void (*destructor)(void *)) {
    return pthread_key_create(key, destructor);
}
__attribute__((weak)) int __wrap_pthread_key_create(pthread_key_t * key, void (*destructor)(void *)) {
    return __real_pthread_key_create(key, destructor);
}

__attribute__((weak)) int __real_pthread_key_delete(pthread_key_t key) {
    return pthread_key_delete(key);
}
__attribute__((weak)) int __wrap_pthread_key_delete(pthread_key_t key) {
    return __real_pthread_key_delete(key);
}

__attribute__((weak)) int __real_pthread_setspecific(pthread_key_t key, const void * value) {
    return pthread_setspecific(key, value);
}
__attribute__((weak)) int __wrap_pthread_setspecific(pthread_key_t key, const void * value) {
    return __real_pthread_setspecific(key, value);
}

__attribute__((weak)) void * __real_pthread_getspecific(pthread_key_t key) {
    return pthread_getspecific(key);
}
__attribute__((weak)) void * __wrap_pthread_getspecific(pthread_key_t key) {
    return __real_pthread_getspecific(key);
}

__attribute__((weak)) int __real_pthread_once(pthread_once_t * once_control, void (*init_routine)(void)) {
    return pthread_once(once_control, init_routine);
}
__attribute__((weak)) int __wrap_pthread_once(pthread_once_t * once_control, void (*init_routine)(void)) {
    return __real_pthread_once(once_control, init_routine);
}

__attribute__((weak)) int __real_pthread_rwlock_init(pthread_rwlock_t * rwlock, const pthread_rwlockattr_t * attr) {
    return pthread_rwlock_init(rwlock, attr);
}
__attribute__((weak)) int __wrap_pthread_rwlock_init(pthread_rwlock_t * rwlock, const pthread_rwlockattr_t * attr) {
    return __real_pthread_rwlock_init(rwlock, attr);
}

__attribute__((weak)) int __real_pthread_rwlock_destroy(pthread_rwlock_t * rwlock) {
    return pthread_rwlock_destroy(rwlock);
}
__attribute__((weak)) int __wrap_pthread_rwlock_destroy(pthread_rwlock_t * rwlock) {
    return __real_pthread_rwlock_destroy(rwlock);
}

__attribute__((weak)) int __real_pthread_rwlock_rdlock(pthread_rwlock_t * rwlock) {
    return pthread_rwlock_rdlock(rwlock);
}
__attribute__((weak)) int __wrap_pthread_rwlock_rdlock(pthread_rwlock_t * rwlock) {
    return __real_pthread_rwlock_rdlock(rwlock);
}

__attribute__((weak)) int __real_pthread_rwlock_tryrdlock(pthread_rwlock_t * rwlock) {
    return pthread_rwlock_tryrdlock(rwlock);
}
__attribute__((weak)) int __wrap_pthread_rwlock_tryrdlock(pthread_rwlock_t * rwlock) {
    return __real_pthread_rwlock_tryrdlock(rwlock);
}

__attribute__((weak)) int __real_pthread_rwlock_wrlock(pthread_rwlock_t * rwlock) {
    return pthread_rwlock_wrlock(rwlock);
}
__attribute__((weak)) int __wrap_pthread_rwlock_wrlock(pthread_rwlock_t * rwlock) {
    return __real_pthread_rwlock_wrlock(rwlock);
}

__attribute__((weak)) int __real_pthread_rwlock_trywrlock(pthread_rwlock_t * rwlock) {
    return pthread_rwlock_trywrlock(rwlock);
}
__attribute__((weak)) int __wrap_pthread_rwlock_trywrlock(pthread_rwlock_t * rwlock) {
    return __real_pthread_rwlock_trywrlock(rwlock);
}

__attribute__((weak)) int __real_pthread_rwlock_unlock(pthread_rwlock_t * rwlock) {
    return pthread_rwlock_unlock(rwlock);
}
__attribute__((weak)) int __wrap_pthread_rwlock_unlock(pthread_rwlock_t * rwlock) {
    return __real_pthread_rwlock_unlock(rwlock);
}

__attribute__((weak)) int __real_pthread_rwlockattr_init(pthread_rwlockattr_t * attr) {
    return pthread_rwlockattr_init(attr);
}
__attribute__((weak)) int __wrap_pthread_rwlockattr_init(pthread_rwlockattr_t * attr) {
    return __real_pthread_rwlockattr_init(attr);
}

__attribute__((weak)) int __real_pthread_rwlockattr_destroy(pthread_rwlockattr_t * attr) {
    return pthread_rwlockattr_destroy(attr);
}
__attribute__((weak)) int __wrap_pthread_rwlockattr_destroy(pthread_rwlockattr_t * attr) {
    return __real_pthread_rwlockattr_destroy(attr);
}

__attribute__((weak)) int __real_pthread_rwlockattr_getpshared(const pthread_rwlockattr_t * attr, int * pshared) {
    return pthread_rwlockattr_getpshared(attr, pshared);
}
__attribute__((weak)) int __wrap_pthread_rwlockattr_getpshared(const pthread_rwlockattr_t * attr, int * pshared) {
    return __real_pthread_rwlockattr_getpshared(attr, pshared);
}

__attribute__((weak)) int __real_pthread_rwlockattr_setpshared(pthread_rwlockattr_t * attr, int pshared) {
    return pthread_rwlockattr_setpshared(attr, pshared);
}
__attribute__((weak)) int __wrap_pthread_rwlockattr_setpshared(pthread_rwlockattr_t * attr, int pshared) {
    return __real_pthread_rwlockattr_setpshared(attr, pshared);
}

__attribute__((weak)) int __real_pthread_rwlockattr_getkind_np(const pthread_rwlockattr_t * attr, int * pref) {
    return pthread_rwlockattr_getkind_np(attr, pref);
}
__attribute__((weak)) int __wrap_pthread_rwlockattr_getkind_np(const pthread_rwlockattr_t * attr, int * pref) {
    return __real_pthread_rwlockattr_getkind_np(attr, pref);
}

__attribute__((weak)) int __real_pthread_rwlockattr_setkind_np(pthread_rwlockattr_t * attr, int pref) {
    return pthread_rwlockattr_setkind_np(attr, pref);
}
__attribute__((weak)) int __wrap_pthread_rwlockattr_setkind_np(pthread_rwlockattr_t * attr, int pref) {
    return __real_pthread_rwlockattr_setkind_np(attr, pref);
}

__attribute__((weak)) int __real_pthread_barrier_init(pthread_barrier_t * barrier, const pthread_barrierattr_t * attr, unsigned int count) {
    return pthread_barrier_init(barrier, attr, count);
}
__attribute__((weak)) int __wrap_pthread_barrier_init(pthread_barrier_t * barrier, const pthread_barrierattr_t * attr, unsigned int count) {
    return __real_pthread_barrier_init(barrier, attr, count);
}

__attribute__((weak)) int __real_pthread_barrier_destroy(pthread_barrier_t * barrier) {
    return pthread_barrier_destroy(barrier);
}
__attribute__((weak)) int __wrap_pthread_barrier_destroy(pthread_barrier_t * barrier) {
    return __real_pthread_barrier_destroy(barrier);
}

__attribute__((weak)) int __real_pthread_barrier_wait(pthread_barrier_t * barrier) {
    return pthread_barrier_wait(barrier);
}
__attribute__((weak)) int __wrap_pthread_barrier_wait(pthread_barrier_t * barrier) {
    return __real_pthread_barrier_wait(barrier);
}

__attribute__((weak)) int __real_pthread_barrierattr_init(pthread_barrierattr_t * attr) {
    return pthread_barrierattr_init(attr);
}
__attribute__((weak)) int __wrap_pthread_barrierattr_init(pthread_barrierattr_t * attr) {
    return __real_pthread_barrierattr_init(attr);
}

__attribute__((weak)) int __real_pthread_barrierattr_destroy(pthread_barrierattr_t * attr) {
    return pthread_barrierattr_destroy(attr);
}
__attribute__((weak)) int __wrap_pthread_barrierattr_destroy(pthread_barrierattr_t * attr) {
    return __real_pthread_barrierattr_destroy(attr);
}

__attribute__((weak)) int __real_pthread_barrierattr_getpshared(const pthread_barrierattr_t * attr, int * pshared) {
    return pthread_barrierattr_getpshared(attr, pshared);
}
__attribute__((weak)) int __wrap_pthread_barrierattr_getpshared(const pthread_barrierattr_t * attr, int * pshared) {
    return __real_pthread_barrierattr_getpshared(attr, pshared);
}

__attribute__((weak)) int __real_pthread_barrierattr_setpshared(pthread_barrierattr_t * attr, int pshared) {
    return pthread_barrierattr_setpshared(attr, pshared);
}
__attribute__((weak)) int __wrap_pthread_barrierattr_setpshared(pthread_barrierattr_t * attr, int pshared) {
    return __real_pthread_barrierattr_setpshared(attr, pshared);
}

__attribute__((weak)) int __real_pthread_spin_init(pthread_spinlock_t * lock, int pshared) {
    return pthread_spin_init(lock, pshared);
}
__attribute__((weak)) int __wrap_pthread_spin_init(pthread_spinlock_t * lock, int pshared) {
    return __real_pthread_spin_init(lock, pshared);
}

__attribute__((weak)) int __real_pthread_spin_destroy(pthread_spinlock_t * lock) {
    return pthread_spin_destroy(lock);
}
__attribute__((weak)) int __wrap_pthread_spin_destroy(pthread_spinlock_t * lock) {
    return __real_pthread_spin_destroy(lock);
}

__attribute__((weak)) int __real_pthread_spin_lock(pthread_spinlock_t * lock) {
    return pthread_spin_lock(lock);
}
__attribute__((weak)) int __wrap_pthread_spin_lock(pthread_spinlock_t * lock) {
    return __real_pthread_spin_lock(lock);
}

__attribute__((weak)) int __real_pthread_spin_trylock(pthread_spinlock_t * lock) {
    return pthread_spin_trylock(lock);
}
__attribute__((weak)) int __wrap_pthread_spin_trylock(pthread_spinlock_t * lock) {
    return __real_pthread_spin_trylock(lock);
}

__attribute__((weak)) int __real_pthread_spin_unlock(pthread_spinlock_t * lock) {
    return pthread_spin_unlock(lock);
}
__attribute__((weak)) int __wrap_pthread_spin_unlock(pthread_spinlock_t * lock) {
    return __real_pthread_spin_unlock(lock);
}

__attribute__((weak)) int __real_getaddrinfo(const char * node, const char * service, const struct addrinfo * hints, struct addrinfo ** res) {
    return getaddrinfo(node, service, hints, res);
}
__attribute__((weak)) int __wrap_getaddrinfo(const char * node, const char * service, const struct addrinfo * hints, struct addrinfo ** res) {
    return __real_getaddrinfo(node, service, hints, res);
}

__attribute__((weak)) void __real_freeaddrinfo(struct addrinfo * res) {
    return freeaddrinfo(res);
}
__attribute__((weak)) void __wrap_freeaddrinfo(struct addrinfo * res) {
    return __real_freeaddrinfo(res);
}

__attribute__((weak)) const char * __real_gai_strerror(int ecode) {
    return gai_strerror(ecode);
}
__attribute__((weak)) const char * __wrap_gai_strerror(int ecode) {
    return __real_gai_strerror(ecode);
}

__attribute__((weak)) int __real_getnameinfo(const struct sockaddr * sa, socklen_t salen, char * host, socklen_t hostlen, char * serv, socklen_t servlen, int flags) {
    return getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
}
__attribute__((weak)) int __wrap_getnameinfo(const struct sockaddr * sa, socklen_t salen, char * host, socklen_t hostlen, char * serv, socklen_t servlen, int flags) {
    return __real_getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
}

__attribute__((weak)) struct hostent * __real_gethostbyname(const char * name) {
    return gethostbyname(name);
}
__attribute__((weak)) struct hostent * __wrap_gethostbyname(const char * name) {
    return __real_gethostbyname(name);
}

__attribute__((weak)) struct hostent * __real_gethostbyaddr(const void * addr, socklen_t len, int type) {
    return gethostbyaddr(addr, len, type);
}
__attribute__((weak)) struct hostent * __wrap_gethostbyaddr(const void * addr, socklen_t len, int type) {
    return __real_gethostbyaddr(addr, len, type);
}

__attribute__((weak)) struct hostent * __real_gethostent() {
    return gethostent();
}
__attribute__((weak)) struct hostent * __wrap_gethostent() {
    return __real_gethostent();
}

__attribute__((weak)) void __real_sethostent(int stayopen) {
    return sethostent(stayopen);
}
__attribute__((weak)) void __wrap_sethostent(int stayopen) {
    return __real_sethostent(stayopen);
}

__attribute__((weak)) void __real_endhostent() {
    return endhostent();
}
__attribute__((weak)) void __wrap_endhostent() {
    return __real_endhostent();
}

__attribute__((weak)) struct netent * __real_getnetbyname(const char * name) {
    return getnetbyname(name);
}
__attribute__((weak)) struct netent * __wrap_getnetbyname(const char * name) {
    return __real_getnetbyname(name);
}

__attribute__((weak)) struct netent * __real_getnetbyaddr(uint32_t net, int type) {
    return getnetbyaddr(net, type);
}
__attribute__((weak)) struct netent * __wrap_getnetbyaddr(uint32_t net, int type) {
    return __real_getnetbyaddr(net, type);
}

__attribute__((weak)) struct netent * __real_getnetent() {
    return getnetent();
}
__attribute__((weak)) struct netent * __wrap_getnetent() {
    return __real_getnetent();
}

__attribute__((weak)) void __real_setnetent(int stayopen) {
    return setnetent(stayopen);
}
__attribute__((weak)) void __wrap_setnetent(int stayopen) {
    return __real_setnetent(stayopen);
}

__attribute__((weak)) void __real_endnetent() {
    return endnetent();
}
__attribute__((weak)) void __wrap_endnetent() {
    return __real_endnetent();
}

__attribute__((weak)) struct protoent * __real_getprotobyname(const char * name) {
    return getprotobyname(name);
}
__attribute__((weak)) struct protoent * __wrap_getprotobyname(const char * name) {
    return __real_getprotobyname(name);
}

__attribute__((weak)) struct protoent * __real_getprotobynumber(int proto) {
    return getprotobynumber(proto);
}
__attribute__((weak)) struct protoent * __wrap_getprotobynumber(int proto) {
    return __real_getprotobynumber(proto);
}

__attribute__((weak)) struct protoent * __real_getprotoent() {
    return getprotoent();
}
__attribute__((weak)) struct protoent * __wrap_getprotoent() {
    return __real_getprotoent();
}

__attribute__((weak)) void __real_setprotoent(int stayopen) {
    return setprotoent(stayopen);
}
__attribute__((weak)) void __wrap_setprotoent(int stayopen) {
    return __real_setprotoent(stayopen);
}

__attribute__((weak)) void __real_endprotoent() {
    return endprotoent();
}
__attribute__((weak)) void __wrap_endprotoent() {
    return __real_endprotoent();
}

__attribute__((weak)) struct servent * __real_getservbyname(const char * name, const char * proto) {
    return getservbyname(name, proto);
}
__attribute__((weak)) struct servent * __wrap_getservbyname(const char * name, const char * proto) {
    return __real_getservbyname(name, proto);
}

__attribute__((weak)) struct servent * __real_getservbyport(int port, const char * proto) {
    return getservbyport(port, proto);
}
__attribute__((weak)) struct servent * __wrap_getservbyport(int port, const char * proto) {
    return __real_getservbyport(port, proto);
}

__attribute__((weak)) struct servent * __real_getservent() {
    return getservent();
}
__attribute__((weak)) struct servent * __wrap_getservent() {
    return __real_getservent();
}

__attribute__((weak)) void __real_setservent(int stayopen) {
    return setservent(stayopen);
}
__attribute__((weak)) void __wrap_setservent(int stayopen) {
    return __real_setservent(stayopen);
}

__attribute__((weak)) void __real_endservent() {
    return endservent();
}
__attribute__((weak)) void __wrap_endservent() {
    return __real_endservent();
}

__attribute__((weak)) struct passwd * __real_getpwuid(uid_t uid) {
    return getpwuid(uid);
}
__attribute__((weak)) struct passwd * __wrap_getpwuid(uid_t uid) {
    return __real_getpwuid(uid);
}

__attribute__((weak)) struct passwd * __real_getpwnam(const char * name) {
    return getpwnam(name);
}
__attribute__((weak)) struct passwd * __wrap_getpwnam(const char * name) {
    return __real_getpwnam(name);
}

__attribute__((weak)) struct passwd * __real_getpwent() {
    return getpwent();
}
__attribute__((weak)) struct passwd * __wrap_getpwent() {
    return __real_getpwent();
}

__attribute__((weak)) void __real_setpwent() {
    return setpwent();
}
__attribute__((weak)) void __wrap_setpwent() {
    return __real_setpwent();
}

__attribute__((weak)) void __real_endpwent() {
    return endpwent();
}
__attribute__((weak)) void __wrap_endpwent() {
    return __real_endpwent();
}

__attribute__((weak)) struct group * __real_getgrgid(gid_t gid) {
    return getgrgid(gid);
}
__attribute__((weak)) struct group * __wrap_getgrgid(gid_t gid) {
    return __real_getgrgid(gid);
}

__attribute__((weak)) struct group * __real_getgrnam(const char * name) {
    return getgrnam(name);
}
__attribute__((weak)) struct group * __wrap_getgrnam(const char * name) {
    return __real_getgrnam(name);
}

__attribute__((weak)) struct group * __real_getgrent() {
    return getgrent();
}
__attribute__((weak)) struct group * __wrap_getgrent() {
    return __real_getgrent();
}

__attribute__((weak)) void __real_setgrent() {
    return setgrent();
}
__attribute__((weak)) void __wrap_setgrent() {
    return __real_setgrent();
}

__attribute__((weak)) void __real_endgrent() {
    return endgrent();
}
__attribute__((weak)) void __wrap_endgrent() {
    return __real_endgrent();
}

__attribute__((weak)) int __real_getlogin_r(char * name, size_t namesize) {
    return getlogin_r(name, namesize);
}
__attribute__((weak)) int __wrap_getlogin_r(char * name, size_t namesize) {
    return __real_getlogin_r(name, namesize);
}

__attribute__((weak)) char * __real_getpass(const char * prompt) {
    return getpass(prompt);
}
__attribute__((weak)) char * __wrap_getpass(const char * prompt) {
    return __real_getpass(prompt);
}

__attribute__((weak)) char * __real_crypt(const char * key, const char * salt) {
    return crypt(key, salt);
}
__attribute__((weak)) char * __wrap_crypt(const char * key, const char * salt) {
    return __real_crypt(key, salt);
}

__attribute__((weak)) char * __real_crypt_r(const char * phrase, const char * setting, struct crypt_data * data) {
    return crypt_r(phrase, setting, data);
}
__attribute__((weak)) char * __wrap_crypt_r(const char * phrase, const char * setting, struct crypt_data * data) {
    return __real_crypt_r(phrase, setting, data);
}

__attribute__((weak)) char * __real_crypt_rn(const char * phrase, const char * setting, struct crypt_data * data, int size) {
    return crypt_rn(phrase, setting, data, size);
}
__attribute__((weak)) char * __wrap_crypt_rn(const char * phrase, const char * setting, struct crypt_data * data, int size) {
    return __real_crypt_rn(phrase, setting, data, size);
}

__attribute__((weak)) char * __real_crypt_ra(const char * phrase, const char * setting, void ** data, int* size) {
    return crypt_ra(phrase, setting, data, size);
}
__attribute__((weak)) char * __wrap_crypt_ra(const char * phrase, const char * setting, void ** data, int* size) {
    return __real_crypt_ra(phrase, setting, data, size);
}

__attribute__((weak)) void __real_qsort(void * base, size_t nmemb, size_t size, int (*compar)(const void *, const void *)) {
    return qsort(base, nmemb, size, compar);
}
__attribute__((weak)) void __wrap_qsort(void * base, size_t nmemb, size_t size, int (*compar)(const void *, const void *)) {
    return __real_qsort(base, nmemb, size, compar);
}

__attribute__((weak)) void __real_qsort_r(void * base, size_t nmemb, size_t size, int (*compar)(const void *, const void *, void *), void * arg) {
    return qsort_r(base, nmemb, size, compar, arg);
}
__attribute__((weak)) void __wrap_qsort_r(void * base, size_t nmemb, size_t size, int (*compar)(const void *, const void *, void *), void * arg) {
    return __real_qsort_r(base, nmemb, size, compar, arg);
}

__attribute__((weak)) void * __real_bsearch(const void * key, const void * base, size_t nmemb, size_t size, int (*compar)(const void *, const void *)) {
    return bsearch(key, base, nmemb, size, compar);
}
__attribute__((weak)) void * __wrap_bsearch(const void * key, const void * base, size_t nmemb, size_t size, int (*compar)(const void *, const void *)) {
    return __real_bsearch(key, base, nmemb, size, compar);
}

__attribute__((weak)) int __real_abs(int j) {
    return abs(j);
}
__attribute__((weak)) int __wrap_abs(int j) {
    return __real_abs(j);
}

__attribute__((weak)) long __real_labs(long j) {
    return labs(j);
}
__attribute__((weak)) long __wrap_labs(long j) {
    return __real_labs(j);
}

__attribute__((weak)) long long __real_llabs(long long j) {
    return llabs(j);
}
__attribute__((weak)) long long __wrap_llabs(long long j) {
    return __real_llabs(j);
}

__attribute__((weak)) div_t __real_div(int numer, int denom) {
    return div(numer, denom);
}
__attribute__((weak)) div_t __wrap_div(int numer, int denom) {
    return __real_div(numer, denom);
}

__attribute__((weak)) ldiv_t __real_ldiv(long numer, long denom) {
    return ldiv(numer, denom);
}
__attribute__((weak)) ldiv_t __wrap_ldiv(long numer, long denom) {
    return __real_ldiv(numer, denom);
}

__attribute__((weak)) lldiv_t __real_lldiv(long long numer, long long denom) {
    return lldiv(numer, denom);
}
__attribute__((weak)) lldiv_t __wrap_lldiv(long long numer, long long denom) {
    return __real_lldiv(numer, denom);
}

__attribute__((weak)) int __real_printf(const char * format, ...) {
    va_list args__wrap_shellphish;
    va_start(args__wrap_shellphish, format);
    return vprintf(format, args__wrap_shellphish);
}
__attribute__((weak)) int __wrap_printf(const char * format, ...) {
    va_list args__wrap_shellphish;
    va_start(args__wrap_shellphish, format);
    return vprintf(format, args__wrap_shellphish);
}

__attribute__((weak)) int __real_fprintf(FILE * stream, const char * format, ...) {
    va_list args__wrap_shellphish;
    va_start(args__wrap_shellphish, format);
    return vfprintf(stream, format, args__wrap_shellphish);
}
__attribute__((weak)) int __wrap_fprintf(FILE * stream, const char * format, ...) {
    va_list args__wrap_shellphish;
    va_start(args__wrap_shellphish, format);
    return vfprintf(stream, format, args__wrap_shellphish);
}

__attribute__((weak)) int __real_sprintf(char * str, const char * format, ...) {
    va_list args__wrap_shellphish;
    va_start(args__wrap_shellphish, format);
    return vsprintf(str, format, args__wrap_shellphish);
}
__attribute__((weak)) int __wrap_sprintf(char * str, const char * format, ...) {
    va_list args__wrap_shellphish;
    va_start(args__wrap_shellphish, format);
    return vsprintf(str, format, args__wrap_shellphish);
}

__attribute__((weak)) int __real_snprintf(char * str, size_t size, const char * format, ...) {
    va_list args__wrap_shellphish;
    va_start(args__wrap_shellphish, format);
    return vsnprintf(str, size, format, args__wrap_shellphish);
}
__attribute__((weak)) int __wrap_snprintf(char * str, size_t size, const char * format, ...) {
    va_list args__wrap_shellphish;
    va_start(args__wrap_shellphish, format);
    return vsnprintf(str, size, format, args__wrap_shellphish);
}

__attribute__((weak)) int __real_scanf(const char * format, ...) {
    va_list args__wrap_shellphish;
    va_start(args__wrap_shellphish, format);
    return vscanf(format, args__wrap_shellphish);
}
__attribute__((weak)) int __wrap_scanf(const char * format, ...) {
    va_list args__wrap_shellphish;
    va_start(args__wrap_shellphish, format);
    return vscanf(format, args__wrap_shellphish);
}

__attribute__((weak)) int __real_fscanf(FILE * stream, const char * format, ...) {
    va_list args__wrap_shellphish;
    va_start(args__wrap_shellphish, format);
    return vfscanf(stream, format, args__wrap_shellphish);
}
__attribute__((weak)) int __wrap_fscanf(FILE * stream, const char * format, ...) {
    va_list args__wrap_shellphish;
    va_start(args__wrap_shellphish, format);
    return vfscanf(stream, format, args__wrap_shellphish);
}

__attribute__((weak)) int __real_sscanf(const char * str, const char * format, ...) {
    va_list args__wrap_shellphish;
    va_start(args__wrap_shellphish, format);
    return vsscanf(str, format, args__wrap_shellphish);
}
__attribute__((weak)) int __wrap_sscanf(const char * str, const char * format, ...) {
    va_list args__wrap_shellphish;
    va_start(args__wrap_shellphish, format);
    return vsscanf(str, format, args__wrap_shellphish);
}


