#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <err.h>
#include <execinfo.h>
#include <pthread.h>
#include <string.h>

int grill_guard_after[100] = {0};
FILE *cov_fp = NULL;
int grill_guard_before[100] = {0};
int done = 0;

#define MAX_FUNC_NAME_LEN 256
#define MAX_FUNCS 1000
#define BUFFER_SIZE (MAX_FUNC_NAME_LEN * MAX_FUNCS)
char *function_names_log;
static int func_count = 0;
static int buffer_offset = 0;
static pthread_mutex_t func_cov_lock = PTHREAD_MUTEX_INITIALIZER;

void func_cov_dump_cov();
void func_cov_set_signal_handler();
//#ifdef GRILLER
//#endif
void _func_cov_dump_cov();

__attribute__((constructor)) void func_cov_init_cov()
{
  char *func_cov_file = getenv("COV_FILE_NAME");
  if (func_cov_file == NULL)
  {
    func_cov_file = "/tmp/func_cov.log";
  }
#ifdef DEBUG
  printf("func_cov_file: %s\n", func_cov_file);
#endif
  
  if (access(func_cov_file, F_OK) != -1)
  {
    remove(func_cov_file);
  }

  function_names_log = calloc(BUFFER_SIZE, sizeof(char));
  if (function_names_log == NULL)
  {
    err(1, "calloc");
    printf("Failed to allocate memory for function names log\n");
    exit(1);
  }

  cov_fp = fopen(func_cov_file, "w");
  if (cov_fp == NULL)
  {
    err(1, "fopen");
    exit(1);
  }
  
  func_cov_set_signal_handler();
  alarm(5);
}

#define PATHMAX 100
#define MAX_STACK_FRAMES 64
static void *stack_traces[MAX_STACK_FRAMES];
static uint8_t alternate_stack[SIGSTKSZ];

void func_cov_set_signal_handler()
{
  /* setup alternate stack */
  {
    stack_t ss = {};
    ss.ss_sp = (void *)alternate_stack;
    ss.ss_size = SIGSTKSZ;
    ss.ss_flags = 0;

    if (sigaltstack(&ss, NULL) != 0)
    {
      err(1, "sigaltstack");
    }
  }

  /* register our signal handlers */
  {
    struct sigaction sig_action = {};
    sig_action.sa_sigaction = func_cov_dump_cov;
    sigemptyset(&sig_action.sa_mask);

    sig_action.sa_flags = SA_SIGINFO | SA_ONSTACK;

    if (sigaction(SIGALRM, &sig_action, NULL) != 0)
    {
      err(1, "sigaction");
    }
    if (sigaction(SIGSEGV, &sig_action, NULL) != 0)
    {
      err(1, "sigaction");
    }
    if (sigaction(SIGFPE, &sig_action, NULL) != 0)
    {
      err(1, "sigaction");
    }
    if (sigaction(SIGINT, &sig_action, NULL) != 0)
    {
      err(1, "sigaction");
    }
    if (sigaction(SIGILL, &sig_action, NULL) != 0)
    {
      err(1, "sigaction");
    }
    if (sigaction(SIGTERM, &sig_action, NULL) != 0)
    {
      err(1, "sigaction");
    }
    if (sigaction(SIGABRT, &sig_action, NULL) != 0)
    {
      err(1, "sigaction");
    }
  }
}

__attribute__((destructor)) void func_cov_dump_cov()
{
  if (done == 1) return;
  done = 1;
  _func_cov_dump_cov();
  if (cov_fp) {
    fflush(cov_fp);
    fclose(cov_fp);
  }
  exit(-1);
}

void func_cov_set_file(char *file_name, int file_name_len, int num_funcs)
{
  if (cov_fp) {
    fwrite(&file_name_len, sizeof(int), 1, cov_fp);
    fwrite(file_name, sizeof(char), file_name_len, cov_fp);
    fwrite(&num_funcs, sizeof(int), 1, cov_fp);
    fflush(cov_fp);
  }
}

// Highly optimized function coverage tracking
void func_cov(char *func_name, int func_name_len)
{
    // Early exit for invalid input
    if (__builtin_expect(func_name == NULL || func_name_len <= 0 || func_name_len > MAX_FUNC_NAME_LEN, 0)) {
        return;
    }

    // Try lock with timeout to avoid blocking
    if (pthread_mutex_trylock(&func_cov_lock) != 0) {
        return; // Skip if can't acquire lock immediately
    }
    
    // Check bounds before copying
    if (__builtin_expect(func_count < MAX_FUNCS && buffer_offset + func_name_len + 1 < BUFFER_SIZE, 1)) {
        // Use fast memory copy
        memcpy(function_names_log + buffer_offset, func_name, func_name_len);
        buffer_offset += func_name_len;
        function_names_log[buffer_offset++] = '\n'; // Add delimiter
        func_count++;
    }
    
    pthread_mutex_unlock(&func_cov_lock);
}

// Dump function that writes all collected data
void _func_cov_dump_cov()
{
    if (cov_fp && function_names_log && buffer_offset > 0) {
        // Write function count first
        fwrite(&func_count, sizeof(int), 1, cov_fp);
        // Write all function names at once
        fwrite(function_names_log, sizeof(char), buffer_offset, cov_fp);
        fflush(cov_fp);
        fsync(fileno(cov_fp));
    }
    
    // Cleanup
    if (function_names_log) {
        free(function_names_log);
        function_names_log = NULL;
    }
}