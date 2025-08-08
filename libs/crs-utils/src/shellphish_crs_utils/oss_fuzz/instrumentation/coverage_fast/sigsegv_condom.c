
// Trace: /home/tracer /out/fuzz_cups /shared/sigsev_seeds/e5589ae7e6c75b33568a120c42b32f14
// Compile: gcc -o tracer tracer.c -ldl 
// Get symbol: nm /out/fuzz_cups | grep __llvm_profile_write_file

#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <signal.h>
#include <dlfcn.h>
#include <signal.h>
#include <string.h>
#include <syscall.h>

unsigned long long LLVM_PROFILE_WRITE_OFFSET;
unsigned char* HARNESS_NAME;

void fflush_coverage(pid_t child) {
    char path[256];
    char line[256];
    char base_address[20]; // Buffer to store the base address
    char *delimiter;
    
    snprintf(path, sizeof(path), "/proc/%d/maps", child);

    FILE *file = fopen(path, "r");
    
    if (!file){
	    printf("Could not find file in /proc");
        perror("fopen");
        return;
    }

    if (fgets(line, sizeof(line), file)) {
        char base_address[20]; // Buffer to store the base address
        char *delimiter;

        // Find the delimiter '-'
        delimiter = strchr(line, '-');
    	
        if (delimiter != NULL) {
        // Copy the part before the delimiter into base_address
            size_t length = delimiter - line; // Length of the first address
            strncpy(base_address, line, length);
            base_address[length] = '\0'; // Null-terminate the string

            unsigned long long address_value = strtoull(base_address, NULL, 16);
            printf("Base address: %p\n", (void *)address_value);
            unsigned long long llvm_write_file_at = address_value + LLVM_PROFILE_WRITE_OFFSET;
            printf("__llvm__write__file at %p\n", (void *)llvm_write_file_at);

	        void *func_address = (void *)llvm_write_file_at;
            // Prepare to call the function in the child process
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, child, NULL, &regs); // Get current registers

            // Set the instruction pointer to the function address
            regs.rip = (unsigned long)func_address;

            // Write the modified registers back to the child process
            ptrace(PTRACE_SETREGS, child, NULL, &regs);
            
            printf("[SIGSEV-CONDOM] Flushing coverage data...\n");
            // Continue execution in the child process
            ptrace(PTRACE_CONT, child, NULL, NULL);
            
            } 
        else {
                printf("Delimiter '-' not found in the line.\n");
                return;
            }
        }
    fclose(file);
}


void handle_segfault(pid_t child) {
    printf("[SIGSEV-CONDOM] Handling SIGSEGV in child process\n");
    fflush(stdout);
    fflush(stderr);

    // Flush the coverage data
    fflush_coverage(child); 

    int status;

    waitpid(child, &status, 0);

    // KILL IT NOW TO AVOID HANGS!
    ptrace(PTRACE_CONT, child, NULL, SIGKILL);

    exit(233);
}

void handle_timeout(pid_t child) {
    printf("[SIGSEV-CONDOM] Handling SIGALRM in child process\n");
    fflush(stdout);
    fflush(stderr);

    // Flush the coverage data
    fflush_coverage(child); 

    int status;

    // Wait for the child process to stop
    waitpid(child, &status, 0);

    // KILL IT NOW TO AVOID HANGS!
    ptrace(PTRACE_CONT, child, NULL, SIGKILL);

    exit(234);
}

int main(int argc, char *argv[]) {

    printf("[SIGSEV-CONDOM] Starting...\n");

    fflush(stdout);

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <program> [args...]\n", argv[0]);
        return 1;
    }

    setvbuf(stdout, NULL, _IONBF, 0); // Disable buffering for stdout
    setvbuf(stderr, NULL, _IONBF, 0); // Disable buffering for stderr

    // This variable is gonna be exported after we fetch
    // the offset of the functions using nm
    const char *env_var = "LLVM_PROFILE_WRITE_OFFSET";
    const char *env_var_two = "HARNESS_NAME";

    char *LLVM_PROFILE_WRITE_FILE_AT = getenv(env_var);
    HARNESS_NAME = getenv(env_var_two);

    // Check if the environment variable is set
    if (LLVM_PROFILE_WRITE_FILE_AT == NULL) {
        fprintf(stderr, "Environment variable %s not set.\n", env_var);
        return 1;
    }

    if (HARNESS_NAME == NULL) {
        fprintf(stderr, "Environment variable %s not set.\n", env_var_two);
        return 1;
    }

    LLVM_PROFILE_WRITE_OFFSET = strtoull(LLVM_PROFILE_WRITE_FILE_AT, NULL, 16);

    printf("LLVM_PROFILE_WRITE_OFFSET: %p\n", (void *)LLVM_PROFILE_WRITE_OFFSET);

    pid_t child = fork();

    if (child == 0) {
        // Tracee: Enable tracing and execute target
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        printf("Executing command %s\n", argv[1]);
        execvp(argv[1], argv+1); // Run target program
        perror("execvp failed");
        return 1;
    } else {
        // Tracer: Monitor the tracee
        int status;
        waitpid(child, &status, 0); // Wait for execvp to trigger stop
        ptrace(PTRACE_CONT, child, NULL, NULL); // Continue execution
        
        int wait_count = 0;

        while (1) {
            waitpid(child, &status, 0);
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                break; // Process exited
            }

            if (WIFSTOPPED(status) && (WSTOPSIG(status) == SIGSEGV || WSTOPSIG(status) == SIGABRT)) {
                printf("[SIGSEV-CONDOM] Child stopped by signal: %d\n", WSTOPSIG(status));
                fflush(stdout);

                // This is exiting the program
                handle_segfault(child);
            }

            if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGALRM) {
                //struct user_regs_struct regs;
                printf("Child stopped by SIGALARM. Forcing Termination.\n");
                //ptrace(PTRACE_GETREGS, child, NULL, &regs);
                //printf("regs.orig_rax is: %lld\n", regs.orig_rax);
                //printf("sys_wait4 is : %lld\n", SYS_wait4);

                // This is exiting the program
                handle_timeout(child); 
            }

            if (WIFSTOPPED(status)){
                printf("Child stopped by signal: %d\n", WSTOPSIG(status));
                fflush(stdout);
                fflush(stderr);
            } else {
                printf("Child is running...\n");
            }

            ptrace(PTRACE_CONT, child, NULL, NULL);
        }
    }
    
    exit(0);
}

