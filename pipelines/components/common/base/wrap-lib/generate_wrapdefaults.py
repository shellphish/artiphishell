

PREFIX='''
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

'''

functions_to_wrap = {
    'exit': {'return_type': 'void', 'args': [('int', 'status')]},
    'open': {'return_type': 'int', 'args': [('const char *', 'path'), ('int', 'flags'), ('mode_t', 'mode')]},
    'close': {'return_type': 'int', 'args': [('int', 'fd')]},
    'read': {'return_type': 'ssize_t', 'args': [('int', 'fd'), ('void *', 'buf'), ('size_t', 'count')]},
    'write': {'return_type': 'ssize_t', 'args': [('int', 'fd'), ('const void *', 'buf'), ('size_t', 'count')]},
    'writev': {'return_type': 'ssize_t', 'args': [('int', 'fd'), ('const struct iovec *', 'iov'), ('int', 'iovcnt')]},
    'lseek': {'return_type': 'off_t', 'args': [('int', 'fd'), ('off_t', 'offset'), ('int', 'whence')]},
    'unlink': {'return_type': 'int', 'args': [('const char *', 'path')]},
    'fstat': {'return_type': 'int', 'args': [('int', 'fd'), ('struct stat *', 'buf')]},
    'stat': {'return_type': 'int', 'args': [('const char *', 'path'), ('struct stat *', 'buf')]},
    'mkdir': {'return_type': 'int', 'args': [('const char *', 'path'), ('mode_t', 'mode')]},
    'rmdir': {'return_type': 'int', 'args': [('const char *', 'path')]},
    'opendir': {'return_type': 'DIR *', 'args': [('const char *', 'name')]},
    'readdir': {'return_type': 'struct dirent *', 'args': [('DIR *', 'dirp')]},
    'closedir': {'return_type': 'int', 'args': [('DIR *', 'dirp')]},
    'getcwd': {'return_type': 'char *', 'args': [('char *', 'buf'), ('size_t', 'size')]},
    'chdir': {'return_type': 'int', 'args': [('const char *', 'path')]},
    'rename': {'return_type': 'int', 'args': [('const char *', 'old'), ('const char *', 'new')]},
    'getpid': {'return_type': 'pid_t', 'args': []},
    'getuid': {'return_type': 'uid_t', 'args': []},
    'geteuid': {'return_type': 'uid_t', 'args': []},
    'getgid': {'return_type': 'gid_t', 'args': []},
    'getegid': {'return_type': 'gid_t', 'args': []},
    'setuid': {'return_type': 'int', 'args': [('uid_t', 'uid')]},
    'setgid': {'return_type': 'int', 'args': [('gid_t', 'gid')]},
    'seteuid': {'return_type': 'int', 'args': [('uid_t', 'uid')]},
    'setegid': {'return_type': 'int', 'args': [('gid_t', 'gid')]},
    'getgroups': {'return_type': 'int', 'args': [('int', 'size'), ('gid_t *', 'list')]},
    'setgroups': {'return_type': 'int', 'args': [('size_t', 'size'), ('const gid_t *', 'list')]},
    'getpgrp': {'return_type': 'pid_t', 'args': []},
    'setpgid': {'return_type': 'int', 'args': [('pid_t', 'pid'), ('pid_t', 'pgid')]},
    'getppid': {'return_type': 'pid_t', 'args': []},
    'setsid': {'return_type': 'pid_t', 'args': []},
    'getpgid': {'return_type': 'pid_t', 'args': [('pid_t', 'pid')]},
    'getlogin': {'return_type': 'char *', 'args': []},
    'gethostname': {'return_type': 'int', 'args': [('char *', 'name'), ('size_t', 'len')]},
    'sethostname': {'return_type': 'int', 'args': [('const char *', 'name'), ('size_t', 'len')]},
    'getdomainname': {'return_type': 'int', 'args': [('char *', 'name'), ('size_t', 'len')]},
    'setdomainname': {'return_type': 'int', 'args': [('const char *', 'name'), ('size_t', 'len')]},
    'getrlimit': {'return_type': 'int', 'args': [('int', 'resource'), ('struct rlimit *', 'rlp')]},
    'setrlimit': {'return_type': 'int', 'args': [('int', 'resource'), ('const struct rlimit *', 'rlp')]},
    'getrusage': {'return_type': 'int', 'args': [('int', 'who'), ('struct rusage *', 'usage')]},
    'times': {'return_type': 'clock_t', 'args': [('struct tms *', 'buf')]},
    'gettimeofday': {'return_type': 'int', 'args': [('struct timeval *', 'tv'), ('struct timezone *', 'tz')]},
    'settimeofday': {'return_type': 'int', 'args': [('const struct timeval *', 'tv'), ('const struct timezone *', 'tz')]},
    'getitimer': {'return_type': 'int', 'args': [('int', 'which'), ('struct itimerval *', 'value')]},
    'setitimer': {'return_type': 'int', 'args': [('int', 'which'), ('const struct itimerval *', 'value'), ('struct itimerval *', 'ovalue')]},
    'srand': {'return_type': 'void', 'args': [('unsigned int', 'seed')]},
    'rand': {'return_type': 'int', 'args': []},
    'rand_r': {'return_type': 'int', 'args': [('unsigned int *', 'seedp')]},
    'malloc': {'return_type': 'void *', 'args': [('size_t', 'size')]},
    'calloc': {'return_type': 'void *', 'args': [('size_t', 'nmemb'), ('size_t', 'size')]},
    'realloc': {'return_type': 'void *', 'args': [('void *', 'ptr'), ('size_t', 'size')]},
    'free': {'return_type': 'void', 'args': [('void *', 'ptr')]},
    'abort': {'return_type': 'void', 'args': []},
    'atexit': {'return_type': 'int', 'args': [('void (*func)(void)', 'func')]},
    'system': {'return_type': 'int', 'args': [('const char *', 'command')]},
    'getenv': {'return_type': 'char *', 'args': [('const char *', 'name')]},
    'putenv': {'return_type': 'int', 'args': [('char *', 'string')]},
    'unsetenv': {'return_type': 'int', 'args': [('const char *', 'name')]},
    'clearenv': {'return_type': 'int', 'args': []},
    'mkstemp': {'return_type': 'int', 'args': [('char *', 'template')]},
    'mkdtemp': {'return_type': 'char *', 'args': [('char *', 'template')]},
    # 'mktemp': {'return_type': 'char *', 'args': [('char *', 'template')]},
    'tmpfile': {'return_type': 'FILE *', 'args': []},
    'tmpnam': {'return_type': 'char *', 'args': [('char *', 's')]},
    'tempnam': {'return_type': 'char *', 'args': [('const char *', 'dir'), ('const char *', 'pfx')]},
    'fclose': {'return_type': 'int', 'args': [('FILE *', 'stream')]},
    'fflush': {'return_type': 'int', 'args': [('FILE *', 'stream')]},
    'fopen': {'return_type': 'FILE *', 'args': [('const char *', 'path'), ('const char *', 'mode')]},
    'freopen': {'return_type': 'FILE *', 'args': [('const char *', 'path'), ('const char *', 'mode'), ('FILE *', 'stream')]},
    'fdopen': {'return_type': 'FILE *', 'args': [('int', 'fd'), ('const char *', 'mode')]},
    'fgetc': {'return_type': 'int', 'args': [('FILE *', 'stream')]},
    'getc': {'return_type': 'int', 'args': [('FILE *', 'stream')]},
    'getchar': {'return_type': 'int', 'args': []},
    'fputc': {'return_type': 'int', 'args': [('int', 'c'), ('FILE *', 'stream')]},
    'putc': {'return_type': 'int', 'args': [('int', 'c'), ('FILE *', 'stream')]},
    'putchar': {'return_type': 'int', 'args': [('int', 'c')]},
    'fgets': {'return_type': 'char *', 'args': [('char *', 's'), ('int', 'size'), ('FILE *', 'stream')]},
    # 'gets': {'return_type': 'char *', 'args': [('char *', 's')]},
    'fputs': {'return_type': 'int', 'args': [('const char *', 's'), ('FILE *', 'stream')]},
    'puts': {'return_type': 'int', 'args': [('const char *', 's')]},
    'feof': {'return_type': 'int', 'args': [('FILE *', 'stream')]},
    'ferror': {'return_type': 'int', 'args': [('FILE *', 'stream')]},
    'clearerr': {'return_type': 'void', 'args': [('FILE *', 'stream')]},
    'fileno': {'return_type': 'int', 'args': [('FILE *', 'stream')]},
    'perror': {'return_type': 'void', 'args': [('const char *', 's')]},
    'fseek': {'return_type': 'int', 'args': [('FILE *', 'stream'), ('long', 'offset'), ('int', 'whence')]},
    'ftell': {'return_type': 'long', 'args': [('FILE *', 'stream')]},
    'rewind': {'return_type': 'void', 'args': [('FILE *', 'stream')]},
    'fread': {'return_type': 'size_t', 'args': [('void *', 'ptr'), ('size_t', 'size'), ('size_t', 'nmemb'), ('FILE *', 'stream')]},
    'fwrite': {'return_type': 'size_t', 'args': [('const void *', 'ptr'), ('size_t', 'size'), ('size_t', 'nmemb'), ('FILE *', 'stream')]},
    'fgetpos': {'return_type': 'int', 'args': [('FILE *', 'stream'), ('fpos_t *', 'pos')]},
    'fsetpos': {'return_type': 'int', 'args': [('FILE *', 'stream'), ('const fpos_t *', 'pos')]},
    'pipe': {'return_type': 'int', 'args': [('int *', 'pipefd')]},
    'dup': {'return_type': 'int', 'args': [('int', 'oldfd')]},
    'dup2': {'return_type': 'int', 'args': [('int', 'oldfd'), ('int', 'newfd')]},
    'fork': {'return_type': 'pid_t', 'args': []},
    'vfork': {'return_type': 'pid_t', 'args': []},
    'wait': {'return_type': 'pid_t', 'args': [('int *', 'status')]},
    'waitpid': {'return_type': 'pid_t', 'args': [('pid_t', 'pid'), ('int *', 'status'), ('int', 'options')]},
    'execv': {'return_type': 'int', 'args': [('const char *', 'path'), ('char *const *', 'argv')]},
    'execve': {'return_type': 'int', 'args': [('const char *', 'path'), ('char *const *', 'argv'), ('char *const *', 'envp')]},
    'execvp': {'return_type': 'int', 'args': [('const char *', 'file'), ('char *const *', 'argv')]},
    'system': {'return_type': 'int', 'args': [('const char *', 'command')]},
    'popen': {'return_type': 'FILE *', 'args': [('const char *', 'command'), ('const char *', 'type')]},
    'pclose': {'return_type': 'int', 'args': [('FILE *', 'stream')]},
    'signal': {'return_type': 'sighandler_t', 'args': [('int', 'signum'), ('sighandler_t', 'handler')]},
    'raise': {'return_type': 'int', 'args': [('int', 'signum')]},
    'kill': {'return_type': 'int', 'args': [('pid_t', 'pid'), ('int', 'signum')]},

    'chmod': {'return_type': 'int', 'args': [('const char *', 'path'), ('mode_t', 'mode')]},
    'chown': {'return_type': 'int', 'args': [('const char *', 'path'), ('uid_t', 'owner'), ('gid_t', 'group')]},
    'utime': {'return_type': 'int', 'args': [('const char *', 'filename'), ('const struct utimbuf *', 'times')]},
    'utimes': {'return_type': 'int', 'args': [('const char *', 'filename'), ('const struct timeval *', 'times')]},
    'fchmod': {'return_type': 'int', 'args': [('int', 'fd'), ('mode_t', 'mode')]},
    'fchown': {'return_type': 'int', 'args': [('int', 'fd'), ('uid_t', 'owner'), ('gid_t', 'group')]},
    'lchown': {'return_type': 'int', 'args': [('const char *', 'path'), ('uid_t', 'owner'), ('gid_t', 'group')]},
    'link': {'return_type': 'int', 'args': [('const char *', 'oldpath'), ('const char *', 'newpath')]},
    'symlink': {'return_type': 'int', 'args': [('const char *', 'oldpath'), ('const char *', 'newpath')]},
    'readlink': {'return_type': 'ssize_t', 'args': [('const char *', 'path'), ('char *', 'buf'), ('size_t', 'bufsiz')]},
    'unlink': {'return_type': 'int', 'args': [('const char *', 'path')]},
    'remove': {'return_type': 'int', 'args': [('const char *', 'path')]},
    'rename': {'return_type': 'int', 'args': [('const char *', 'oldpath'), ('const char *', 'newpath')]},
    'mkdir': {'return_type': 'int', 'args': [('const char *', 'path'), ('mode_t', 'mode')]},
    'rmdir': {'return_type': 'int', 'args': [('const char *', 'path')]},
    'chdir': {'return_type': 'int', 'args': [('const char *', 'path')]},
    'getcwd': {'return_type': 'char *', 'args': [('char *', 'buf'), ('size_t', 'size')]},
    'realpath': {'return_type': 'char *', 'args': [('const char *', 'path'), ('char *', 'resolved_path')]},
    'stat': {'return_type': 'int', 'args': [('const char *', 'path'), ('struct stat *', 'buf')]},
    'fstat': {'return_type': 'int', 'args': [('int', 'fd'), ('struct stat *', 'buf')]},
    'lstat': {'return_type': 'int', 'args': [('const char *', 'path'), ('struct stat *', 'buf')]},
    'fstatat': {'return_type': 'int', 'args': [('int', 'dirfd'), ('const char *', 'pathname'), ('struct stat *', 'buf'), ('int', 'flags')]},
    'access': {'return_type': 'int', 'args': [('const char *', 'pathname'), ('int', 'mode')]},
    'euidaccess': {'return_type': 'int', 'args': [('const char *', 'pathname'), ('int', 'mode')]},
    'faccessat': {'return_type': 'int', 'args': [('int', 'dirfd'), ('const char *', 'pathname'), ('int', 'mode'), ('int', 'flags')]},

    'select': {'return_type': 'int', 'args': [('int', 'nfds'), ('fd_set *', 'readfds'), ('fd_set *', 'writefds'), ('fd_set *', 'exceptfds'), ('struct timeval *', 'timeout')]},
    'poll': {'return_type': 'int', 'args': [('struct pollfd *', 'fds'), ('nfds_t', 'nfds'), ('int', 'timeout')]},
    'ppoll': {'return_type': 'int', 'args': [('struct pollfd *', 'fds'), ('nfds_t', 'nfds'), ('const struct timespec *', 'tmo_p'), ('const sigset_t *', 'sigmask')]},
    'epoll_create': {'return_type': 'int', 'args': [('int', 'size')]},
    'epoll_create1': {'return_type': 'int', 'args': [('int', 'flags')]},
    'epoll_ctl': {'return_type': 'int', 'args': [('int', 'epfd'), ('int', 'op'), ('int', 'fd'), ('struct epoll_event *', 'event')]},
    'epoll_wait': {'return_type': 'int', 'args': [('int', 'epfd'), ('struct epoll_event *', 'events'), ('int', 'maxevents'), ('int', 'timeout')]},
    'epoll_pwait': {'return_type': 'int', 'args': [('int', 'epfd'), ('struct epoll_event *', 'events'), ('int', 'maxevents'), ('int', 'timeout'), ('const sigset_t *', 'sigmask')]},

    'ioctl': {'return_type': 'int', 'args': [('int', 'fd'), ('unsigned long', 'request'), ('void *', 'arg')]},
    'fcntl': {'return_type': 'int', 'args': [('int', 'fd'), ('int', 'cmd'), ('void *', 'arg')]},

    'getsockopt': {'return_type': 'int', 'args': [('int', 'sockfd'), ('int', 'level'), ('int', 'optname'), ('void *', 'optval'), ('socklen_t *', 'optlen')]},
    'setsockopt': {'return_type': 'int', 'args': [('int', 'sockfd'), ('int', 'level'), ('int', 'optname'), ('const void *', 'optval'), ('socklen_t', 'optlen')]},
    'socket': {'return_type': 'int', 'args': [('int', 'domain'), ('int', 'type'), ('int', 'protocol')]},
    'socketpair': {'return_type': 'int', 'args': [('int', 'domain'), ('int', 'type'), ('int', 'protocol'), ('int *', 'sv')]},
    'bind': {'return_type': 'int', 'args': [('int', 'sockfd'), ('const struct sockaddr *', 'addr'), ('socklen_t', 'addrlen')]},
    'listen': {'return_type': 'int', 'args': [('int', 'sockfd'), ('int', 'backlog')]},
    'accept': {'return_type': 'int', 'args': [('int', 'sockfd'), ('struct sockaddr *', 'addr'), ('socklen_t *', 'addrlen')]},
    # 'accept4': {'return_type': 'int', 'args': [('int', 'sockfd'), ('struct sockaddr *', 'addr'), ('socklen_t *', 'addrlen'), ('int', 'flags')]},
    'connect': {'return_type': 'int', 'args': [('int', 'sockfd'), ('const struct sockaddr *', 'addr'), ('socklen_t', 'addrlen')]},
    'shutdown': {'return_type': 'int', 'args': [('int', 'sockfd'), ('int', 'how')]},
    'send': {'return_type': 'ssize_t', 'args': [('int', 'sockfd'), ('const void *', 'buf'), ('size_t', 'len'), ('int', 'flags')]},
    'recv': {'return_type': 'ssize_t', 'args': [('int', 'sockfd'), ('void *', 'buf'), ('size_t', 'len'), ('int', 'flags')]},
    'sendto': {'return_type': 'ssize_t', 'args': [('int', 'sockfd'), ('const void *', 'buf'), ('size_t', 'len'), ('int', 'flags'), ('const struct sockaddr *', 'dest_addr'), ('socklen_t', 'addrlen')]},
    'recvfrom': {'return_type': 'ssize_t', 'args': [('int', 'sockfd'), ('void *', 'buf'), ('size_t', 'len'), ('int', 'flags'), ('struct sockaddr *', 'src_addr'), ('socklen_t *', 'addrlen')]},
    'getsockname': {'return_type': 'int', 'args': [('int', 'sockfd'), ('struct sockaddr *', 'addr'), ('socklen_t *', 'addrlen')]},
    'getpeername': {'return_type': 'int', 'args': [('int', 'sockfd'), ('struct sockaddr *', 'addr'), ('socklen_t *', 'addrlen')]},
    'sendmsg': {'return_type': 'ssize_t', 'args': [('int', 'sockfd'), ('const struct msghdr *', 'msg'), ('int', 'flags')]},
    'recvmsg': {'return_type': 'ssize_t', 'args': [('int', 'sockfd'), ('struct msghdr *', 'msg'), ('int', 'flags')]},

    'pthread_create': {'return_type': 'int', 'args': [('pthread_t *', 'thread'), ('const pthread_attr_t *', 'attr'), ('void *(*start_routine)(void *)', 'start_routine'), ('void *', 'arg')]},
    'pthread_exit': {'return_type': 'void', 'args': [('void *', 'value_ptr')]},
    'pthread_join': {'return_type': 'int', 'args': [('pthread_t', 'thread'), ('void **', 'value_ptr')]},
    'pthread_detach': {'return_type': 'int', 'args': [('pthread_t', 'thread')]},
    'pthread_self': {'return_type': 'pthread_t', 'args': []},
    'pthread_equal': {'return_type': 'int', 'args': [('pthread_t', 't1'), ('pthread_t', 't2')]},
    'pthread_cancel': {'return_type': 'int', 'args': [('pthread_t', 'thread')]},
    'pthread_setcancelstate': {'return_type': 'int', 'args': [('int', 'state'), ('int *', 'oldstate')]},
    'pthread_setcanceltype': {'return_type': 'int', 'args': [('int', 'type'), ('int *', 'oldtype')]},
    'pthread_testcancel': {'return_type': 'void', 'args': []},
    'pthread_attr_init': {'return_type': 'int', 'args': [('pthread_attr_t *', 'attr')]},
    'pthread_attr_destroy': {'return_type': 'int', 'args': [('pthread_attr_t *', 'attr')]},
    'pthread_attr_getdetachstate': {'return_type': 'int', 'args': [('const pthread_attr_t *', 'attr'), ('int *', 'detachstate')]},
    'pthread_attr_setdetachstate': {'return_type': 'int', 'args': [('pthread_attr_t *', 'attr'), ('int', 'detachstate')]},
    'pthread_attr_getstacksize': {'return_type': 'int', 'args': [('const pthread_attr_t *', 'attr'), ('size_t *', 'stacksize')]},
    'pthread_attr_setstacksize': {'return_type': 'int', 'args': [('pthread_attr_t *', 'attr'), ('size_t', 'stacksize')]},
    # 'pthread_attr_getstackaddr': {'return_type': 'int', 'args': [('const pthread_attr_t *', 'attr'), ('void **', 'stackaddr')]},
    # 'pthread_attr_setstackaddr': {'return_type': 'int', 'args': [('pthread_attr_t *', 'attr'), ('void *', 'stackaddr')]},
    'pthread_attr_getguardsize': {'return_type': 'int', 'args': [('const pthread_attr_t *', 'attr'), ('size_t *', 'guardsize')]},
    'pthread_attr_setguardsize': {'return_type': 'int', 'args': [('pthread_attr_t *', 'attr'), ('size_t', 'guardsize')]},
    'pthread_attr_getschedparam': {'return_type': 'int', 'args': [('const pthread_attr_t *', 'attr'), ('struct sched_param *', 'param')]},
    'pthread_attr_setschedparam': {'return_type': 'int', 'args': [('pthread_attr_t *', 'attr'), ('const struct sched_param *', 'param')]},
    'pthread_attr_getschedpolicy': {'return_type': 'int', 'args': [('const pthread_attr_t *', 'attr'), ('int *', 'policy')]},
    'pthread_attr_setschedpolicy': {'return_type': 'int', 'args': [('pthread_attr_t *', 'attr'), ('int', 'policy')]},
    'pthread_attr_getinheritsched': {'return_type': 'int', 'args': [('const pthread_attr_t *', 'attr'), ('int *', 'inheritsched')]},
    'pthread_attr_setinheritsched': {'return_type': 'int', 'args': [('pthread_attr_t *', 'attr'), ('int', 'inheritsched')]},
    'pthread_attr_getscope': {'return_type': 'int', 'args': [('const pthread_attr_t *', 'attr'), ('int *', 'scope')]},
    'pthread_attr_setscope': {'return_type': 'int', 'args': [('pthread_attr_t *', 'attr'), ('int', 'scope')]},
    'pthread_attr_getstack': {'return_type': 'int', 'args': [('const pthread_attr_t *', 'attr'), ('void **', 'stackaddr'), ('size_t *', 'stacksize')]},
    'pthread_attr_setstack': {'return_type': 'int', 'args': [('pthread_attr_t *', 'attr'), ('void *', 'stackaddr'), ('size_t', 'stacksize')]},
    'pthread_getattr_default_np': {'return_type': 'int', 'args': [('pthread_attr_t *', 'attr')]},
    'pthread_setattr_default_np': {'return_type': 'int', 'args': [('const pthread_attr_t *', 'attr')]},
    'pthread_mutex_init': {'return_type': 'int', 'args': [('pthread_mutex_t *', 'mutex'), ('const pthread_mutexattr_t *', 'attr')]},
    'pthread_mutex_destroy': {'return_type': 'int', 'args': [('pthread_mutex_t *', 'mutex')]},
    'pthread_mutex_lock': {'return_type': 'int', 'args': [('pthread_mutex_t *', 'mutex')]},
    'pthread_mutex_trylock': {'return_type': 'int', 'args': [('pthread_mutex_t *', 'mutex')]},
    'pthread_mutex_unlock': {'return_type': 'int', 'args': [('pthread_mutex_t *', 'mutex')]},
    'pthread_mutexattr_init': {'return_type': 'int', 'args': [('pthread_mutexattr_t *', 'attr')]},
    'pthread_mutexattr_destroy': {'return_type': 'int', 'args': [('pthread_mutexattr_t *', 'attr')]},
    'pthread_mutexattr_getpshared': {'return_type': 'int', 'args': [('const pthread_mutexattr_t *', 'attr'), ('int *', 'pshared')]},
    'pthread_mutexattr_setpshared': {'return_type': 'int', 'args': [('pthread_mutexattr_t *', 'attr'), ('int', 'pshared')]},
    'pthread_mutexattr_gettype': {'return_type': 'int', 'args': [('const pthread_mutexattr_t *', 'attr'), ('int *', 'type')]},
    'pthread_mutexattr_settype': {'return_type': 'int', 'args': [('pthread_mutexattr_t *', 'attr'), ('int', 'type')]},
    'pthread_mutexattr_getprotocol': {'return_type': 'int', 'args': [('const pthread_mutexattr_t *', 'attr'), ('int *', 'protocol')]},
    'pthread_mutexattr_setprotocol': {'return_type': 'int', 'args': [('pthread_mutexattr_t *', 'attr'), ('int', 'protocol')]},
    'pthread_mutexattr_getprioceiling': {'return_type': 'int', 'args': [('const pthread_mutexattr_t *', 'attr'), ('int *', 'prioceiling')]},
    'pthread_mutexattr_setprioceiling': {'return_type': 'int', 'args': [('pthread_mutexattr_t *', 'attr'), ('int', 'prioceiling')]},
    'pthread_mutexattr_getprioceiling': {'return_type': 'int', 'args': [('const pthread_mutexattr_t *', 'attr'), ('int *', 'prioceiling')]},
    'pthread_mutexattr_setprioceiling': {'return_type': 'int', 'args': [('pthread_mutexattr_t *', 'attr'), ('int', 'prioceiling')]},
    'pthread_mutexattr_getprotocol': {'return_type': 'int', 'args': [('const pthread_mutexattr_t *', 'attr'), ('int *', 'protocol')]},
    'pthread_mutexattr_setprotocol': {'return_type': 'int', 'args': [('pthread_mutexattr_t *', 'attr'), ('int', 'protocol')]},
    
    'pthread_cond_init': {'return_type': 'int', 'args': [('pthread_cond_t *', 'cond'), ('const pthread_condattr_t *', 'attr')]},
    'pthread_cond_destroy': {'return_type': 'int', 'args': [('pthread_cond_t *', 'cond')]},
    'pthread_cond_wait': {'return_type': 'int', 'args': [('pthread_cond_t *', 'cond'), ('pthread_mutex_t *', 'mutex')]},
    'pthread_cond_timedwait': {'return_type': 'int', 'args': [('pthread_cond_t *', 'cond'), ('pthread_mutex_t *', 'mutex'), ('const struct timespec *', 'abstime')]},
    'pthread_cond_signal': {'return_type': 'int', 'args': [('pthread_cond_t *', 'cond')]},
    'pthread_cond_broadcast': {'return_type': 'int', 'args': [('pthread_cond_t *', 'cond')]},
    'pthread_condattr_init': {'return_type': 'int', 'args': [('pthread_condattr_t *', 'attr')]},
    'pthread_condattr_destroy': {'return_type': 'int', 'args': [('pthread_condattr_t *', 'attr')]},
    'pthread_condattr_getpshared': {'return_type': 'int', 'args': [('const pthread_condattr_t *', 'attr'), ('int *', 'pshared')]},
    'pthread_condattr_setpshared': {'return_type': 'int', 'args': [('pthread_condattr_t *', 'attr'), ('int', 'pshared')]},
    'pthread_condattr_getclock': {'return_type': 'int', 'args': [('const pthread_condattr_t *', 'attr'), ('clockid_t *', 'clock')]},
    'pthread_condattr_setclock': {'return_type': 'int', 'args': [('pthread_condattr_t *', 'attr'), ('clockid_t', 'clock')]},
    'pthread_key_create': {'return_type': 'int', 'args': [('pthread_key_t *', 'key'), ('void (*destructor)(void *)', 'destructor')]},
    'pthread_key_delete': {'return_type': 'int', 'args': [('pthread_key_t', 'key')]},
    'pthread_setspecific': {'return_type': 'int', 'args': [('pthread_key_t', 'key'), ('const void *', 'value')]},
    'pthread_getspecific': {'return_type': 'void *', 'args': [('pthread_key_t', 'key')]},
    'pthread_once': {'return_type': 'int', 'args': [('pthread_once_t *', 'once_control'), ('void (*init_routine)(void)', 'init_routine')]},
    'pthread_rwlock_init': {'return_type': 'int', 'args': [('pthread_rwlock_t *', 'rwlock'), ('const pthread_rwlockattr_t *', 'attr')]},
    'pthread_rwlock_destroy': {'return_type': 'int', 'args': [('pthread_rwlock_t *', 'rwlock')]},
    'pthread_rwlock_rdlock': {'return_type': 'int', 'args': [('pthread_rwlock_t *', 'rwlock')]},
    'pthread_rwlock_tryrdlock': {'return_type': 'int', 'args': [('pthread_rwlock_t *', 'rwlock')]},
    'pthread_rwlock_wrlock': {'return_type': 'int', 'args': [('pthread_rwlock_t *', 'rwlock')]},
    'pthread_rwlock_trywrlock': {'return_type': 'int', 'args': [('pthread_rwlock_t *', 'rwlock')]},
    'pthread_rwlock_unlock': {'return_type': 'int', 'args': [('pthread_rwlock_t *', 'rwlock')]},
    'pthread_rwlockattr_init': {'return_type': 'int', 'args': [('pthread_rwlockattr_t *', 'attr')]},
    'pthread_rwlockattr_destroy': {'return_type': 'int', 'args': [('pthread_rwlockattr_t *', 'attr')]},
    'pthread_rwlockattr_getpshared': {'return_type': 'int', 'args': [('const pthread_rwlockattr_t *', 'attr'), ('int *', 'pshared')]},
    'pthread_rwlockattr_setpshared': {'return_type': 'int', 'args': [('pthread_rwlockattr_t *', 'attr'), ('int', 'pshared')]},
    'pthread_rwlockattr_getkind_np': {'return_type': 'int', 'args': [('const pthread_rwlockattr_t *', 'attr'), ('int *', 'pref')]},
    'pthread_rwlockattr_setkind_np': {'return_type': 'int', 'args': [('pthread_rwlockattr_t *', 'attr'), ('int', 'pref')]},
    'pthread_barrier_init': {'return_type': 'int', 'args': [('pthread_barrier_t *', 'barrier'), ('const pthread_barrierattr_t *', 'attr'), ('unsigned int', 'count')]},
    'pthread_barrier_destroy': {'return_type': 'int', 'args': [('pthread_barrier_t *', 'barrier')]},
    'pthread_barrier_wait': {'return_type': 'int', 'args': [('pthread_barrier_t *', 'barrier')]},
    'pthread_barrierattr_init': {'return_type': 'int', 'args': [('pthread_barrierattr_t *', 'attr')]},
    'pthread_barrierattr_destroy': {'return_type': 'int', 'args': [('pthread_barrierattr_t *', 'attr')]},
    'pthread_barrierattr_getpshared': {'return_type': 'int', 'args': [('const pthread_barrierattr_t *', 'attr'), ('int *', 'pshared')]},
    'pthread_barrierattr_setpshared': {'return_type': 'int', 'args': [('pthread_barrierattr_t *', 'attr'), ('int', 'pshared')]},
    'pthread_barrierattr_getpshared': {'return_type': 'int', 'args': [('const pthread_barrierattr_t *', 'attr'), ('int *', 'pshared')]},
    'pthread_barrierattr_setpshared': {'return_type': 'int', 'args': [('pthread_barrierattr_t *', 'attr'), ('int', 'pshared')]},
    'pthread_spin_init': {'return_type': 'int', 'args': [('pthread_spinlock_t *', 'lock'), ('int', 'pshared')]},
    'pthread_spin_destroy': {'return_type': 'int', 'args': [('pthread_spinlock_t *', 'lock')]},
    'pthread_spin_lock': {'return_type': 'int', 'args': [('pthread_spinlock_t *', 'lock')]},
    'pthread_spin_trylock': {'return_type': 'int', 'args': [('pthread_spinlock_t *', 'lock')]},
    'pthread_spin_unlock': {'return_type': 'int', 'args': [('pthread_spinlock_t *', 'lock')]},
    'pthread_barrierattr_getpshared': {'return_type': 'int', 'args': [('const pthread_barrierattr_t *', 'attr'), ('int *', 'pshared')]},
    'pthread_barrierattr_setpshared': {'return_type': 'int', 'args': [('pthread_barrierattr_t *', 'attr'), ('int', 'pshared')]},
    'pthread_barrierattr_getpshared': {'return_type': 'int', 'args': [('const pthread_barrierattr_t *', 'attr'), ('int *', 'pshared')]},
    'pthread_barrierattr_setpshared': {'return_type': 'int', 'args': [('pthread_barrierattr_t *', 'attr'), ('int', 'pshared')]},
    'pthread_spin_init': {'return_type': 'int', 'args': [('pthread_spinlock_t *', 'lock'), ('int', 'pshared')]},
    'pthread_spin_destroy': {'return_type': 'int', 'args': [('pthread_spinlock_t *', 'lock')]},
    'pthread_spin_lock': {'return_type': 'int', 'args': [('pthread_spinlock_t *', 'lock')]},
    'pthread_spin_trylock': {'return_type': 'int', 'args': [('pthread_spinlock_t *', 'lock')]},
    'pthread_spin_unlock': {'return_type': 'int', 'args': [('pthread_spinlock_t *', 'lock')]},

    'getaddrinfo': {'return_type': 'int', 'args': [('const char *', 'node'), ('const char *', 'service'), ('const struct addrinfo *', 'hints'), ('struct addrinfo **', 'res')]},
    'freeaddrinfo': {'return_type': 'void', 'args': [('struct addrinfo *', 'res')]},
    'gai_strerror': {'return_type': 'const char *', 'args': [('int', 'ecode')]},
    'getnameinfo': {'return_type': 'int', 'args': [('const struct sockaddr *', 'sa'), ('socklen_t', 'salen'), ('char *', 'host'), ('socklen_t', 'hostlen'), ('char *', 'serv'), ('socklen_t', 'servlen'), ('int', 'flags')]},
    'gethostbyname': {'return_type': 'struct hostent *', 'args': [('const char *', 'name')]},
    'gethostbyaddr': {'return_type': 'struct hostent *', 'args': [('const void *', 'addr'), ('socklen_t', 'len'), ('int', 'type')]},
    'gethostent': {'return_type': 'struct hostent *', 'args': []},
    'sethostent': {'return_type': 'void', 'args': [('int', 'stayopen')]},
    'endhostent': {'return_type': 'void', 'args': []},
    'getnetbyname': {'return_type': 'struct netent *', 'args': [('const char *', 'name')]},
    'getnetbyaddr': {'return_type': 'struct netent *', 'args': [('uint32_t', 'net'), ('int', 'type')]},
    'getnetent': {'return_type': 'struct netent *', 'args': []},
    'setnetent': {'return_type': 'void', 'args': [('int', 'stayopen')]},
    'endnetent': {'return_type': 'void', 'args': []},
    'getprotobyname': {'return_type': 'struct protoent *', 'args': [('const char *', 'name')]},
    'getprotobynumber': {'return_type': 'struct protoent *', 'args': [('int', 'proto')]},
    'getprotoent': {'return_type': 'struct protoent *', 'args': []},
    'setprotoent': {'return_type': 'void', 'args': [('int', 'stayopen')]},
    'endprotoent': {'return_type': 'void', 'args': []},
    'getservbyname': {'return_type': 'struct servent *', 'args': [('const char *', 'name'), ('const char *', 'proto')]},
    'getservbyport': {'return_type': 'struct servent *', 'args': [('int', 'port'), ('const char *', 'proto')]},
    'getservent': {'return_type': 'struct servent *', 'args': []},
    'setservent': {'return_type': 'void', 'args': [('int', 'stayopen')]},
    'endservent': {'return_type': 'void', 'args': []},
    'getpwuid': {'return_type': 'struct passwd *', 'args': [('uid_t', 'uid')]},
    'getpwnam': {'return_type': 'struct passwd *', 'args': [('const char *', 'name')]},
    'getpwent': {'return_type': 'struct passwd *', 'args': []},
    'setpwent': {'return_type': 'void', 'args': []},
    'endpwent': {'return_type': 'void', 'args': []},
    'getgrgid': {'return_type': 'struct group *', 'args': [('gid_t', 'gid')]},
    'getgrnam': {'return_type': 'struct group *', 'args': [('const char *', 'name')]},
    'getgrent': {'return_type': 'struct group *', 'args': []},
    'setgrent': {'return_type': 'void', 'args': []},
    'endgrent': {'return_type': 'void', 'args': []},
    'getlogin_r': {'return_type': 'int', 'args': [('char *', 'name'), ('size_t', 'namesize')]},
    'getpass': {'return_type': 'char *', 'args': [('const char *', 'prompt')]},
    'crypt': {'return_type': 'char *', 'args': [('const char *', 'key'), ('const char *', 'salt')]},
    'crypt_r': {'return_type': 'char *', 'args': [('const char *', 'phrase'), ('const char *', 'setting'), ('struct crypt_data *', 'data')]},
    'crypt_rn': {'return_type': 'char *', 'args': [('const char *', 'phrase'), ('const char *', 'setting'), ('struct crypt_data *', 'data'), ('int', 'size')]},
    'crypt_ra': {'return_type': 'char *', 'args': [('const char *', 'phrase'), ('const char *', 'setting'), ('void **', 'data'), ('int*', 'size')]},

    'qsort': {'return_type': 'void', 'args': [('void *', 'base'), ('size_t', 'nmemb'), ('size_t', 'size'), ('int (*compar)(const void *, const void *)', 'compar')]},
    'qsort_r': {'return_type': 'void', 'args': [('void *', 'base'), ('size_t', 'nmemb'), ('size_t', 'size'), ('int (*compar)(const void *, const void *, void *)', 'compar'), ('void *', 'arg')]},
    'bsearch': {'return_type': 'void *', 'args': [('const void *', 'key'), ('const void *', 'base'), ('size_t', 'nmemb'), ('size_t', 'size'), ('int (*compar)(const void *, const void *)', 'compar')]},
    'abs': {'return_type': 'int', 'args': [('int', 'j')]},
    'labs': {'return_type': 'long', 'args': [('long', 'j')]},
    'llabs': {'return_type': 'long long', 'args': [('long long', 'j')]},
    'div': {'return_type': 'div_t', 'args': [('int', 'numer'), ('int', 'denom')]},
    'ldiv': {'return_type': 'ldiv_t', 'args': [('long', 'numer'), ('long', 'denom')]},
    'lldiv': {'return_type': 'lldiv_t', 'args': [('long long', 'numer'), ('long long', 'denom')]},
}

# only functions with varargs with ...
vararg_functions_to_wrap = {
    # stdio functions
    'printf': {'return_type': 'int', 'fmt_arg': 'format', 'varg_equivalent': 'vprintf', 'args': [('const char *', 'format'), ('...')]},
    'fprintf': {'return_type': 'int', 'fmt_arg': 'format', 'varg_equivalent': 'vfprintf', 'args': [('FILE *', 'stream'), ('const char *', 'format'), ('...')]},
    'sprintf': {'return_type': 'int', 'fmt_arg': 'format', 'varg_equivalent': 'vsprintf', 'args': [('char *', 'str'), ('const char *', 'format'), ('...')]},
    'snprintf': {'return_type': 'int', 'fmt_arg': 'format', 'varg_equivalent': 'vsnprintf', 'args': [('char *', 'str'), ('size_t', 'size'), ('const char *', 'format'), ('...')]},
    'scanf': {'return_type': 'int', 'fmt_arg': 'format', 'varg_equivalent': 'vscanf', 'args': [('const char *', 'format'), ('...')]},
    'fscanf': {'return_type': 'int', 'fmt_arg': 'format', 'varg_equivalent': 'vfscanf', 'args': [('FILE *', 'stream'), ('const char *', 'format'), ('...')]},
    'sscanf': {'return_type': 'int', 'fmt_arg': 'format', 'varg_equivalent': 'vsscanf', 'args': [('const char *', 'str'), ('const char *', 'format'), ('...')]},
}

EXTRA_WRAPPED_FUNCTIONS = '''
'''

RESULT = PREFIX
for function, details in functions_to_wrap.items():
    args_with_types = ', '.join(
            f'{arg_type} {arg_name}'
        if f'(*{arg_name})' not in arg_type else
            arg_type
        for arg_type, arg_name in details['args']
    )
    args = ', '.join(arg[1] for arg in details['args'])
    RESULT += f'''
__attribute__((weak)) {details['return_type']} __real_{function}({args_with_types}) {{
    return {function}({args});
}}
__attribute__((weak)) {details['return_type']} __wrap_{function}({args_with_types}) {{
    return __real_{function}({args});
}}
'''
    
for function, details in vararg_functions_to_wrap.items():
    assert details['args'][-1] == '...', f"Last argument of {function} must be '...'"
    args_with_types = ', '.join(' '.join(arg) for arg in details['args'][:-1])
    args = ', '.join(arg[1] for arg in details['args'][:-1])
    fmt_arg = details['fmt_arg']
    RESULT += f'''
__attribute__((weak)) {details['return_type']} __real_{function}({args_with_types}, ...) {{
    va_list args__wrap_shellphish;
    va_start(args__wrap_shellphish, {fmt_arg});
    return {details['varg_equivalent']}({args}, args__wrap_shellphish);
}}
__attribute__((weak)) {details['return_type']} __wrap_{function}({args_with_types}, ...) {{
    va_list args__wrap_shellphish;
    va_start(args__wrap_shellphish, {fmt_arg});
    return {details['varg_equivalent']}({args}, args__wrap_shellphish);
}}
'''
    
RESULT += EXTRA_WRAPPED_FUNCTIONS

print(RESULT)