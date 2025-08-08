#include <stdio.h>
#include <string.h>
// Assume IJON runtime is linked and provides the IJON macros described above

int main() {
    // (1) Retrieve some fuzz input values (abstracted for example)
    int x   = get_fuzz_int();         // an integer from fuzz input
    int a   = get_fuzz_int();         // another integer
    int b   = get_fuzz_int();         // another integer
    char *s = get_fuzz_string();      // a fuzzed input string
    
    // (2) IJON_ASSUME-like usage: restrict fuzzing to a condition
    ijon_disable_feedback();                  // ignore coverage until condition is met
    if (x < 0) {
        ijon_enable_feedback();               // enable coverage only for inputs with x < 0
    }
    // Only executions where x is negative will produce new coverage beyond this point.
    
    // (3) IJON_TRACE via INC/SET: expose internal state changes
    static int prev_x = 0;
    if (x != prev_x) {
        IJON_INC(x);                // treat each new value of x as new coverage
        prev_x = x;
    }
    // Now the fuzzer is rewarded for finding inputs that produce new values of x.
    IJON_SET(x);                    // mark this particular value of x as seen (one-time)
    // The fuzzer will try to hit as many unique x values as possible.
    
    // (4) IJON_STATE: incorporate a virtual state for even/odd cases every edge will trigger new coverage for that state after this is set
    if ((x % 2) == 0) {
        IJON_CTX(1);             // enter state "1" for even case
    } else {
        IJON_CTX(2);             // enter state "2" for odd case
    }
    // The following code executes under a state tag (1 or 2) that makes coverage context-sensitive.
    // For example, an inner function might have different behavior in even vs odd state.
    check_complex_condition(a, b); // (some function that may be executed in both contexts)
    // Revert state before exiting the branch (so that states don't leak outside scope)
    if ((x % 2) == 0) IJON_CTX(1); else IJON_CTX(2);
    
    // (5) IJON_CMP: guide bit-by-bit towards a target value
    int key = 0xDEADBEEF;
    IJON_CMP(x, key);             // provide feedback on matching bits between x and 0xDEADBEEF
    IJON_CMP(x, 0xC0DECAFE);      // provide feedback on matching bits between x and 0xC0DECAFE
    if (x == key) {
        printf("Secret unlocked!\\n");
        // ... perhaps trigger a bug here ...
    } else if (x == 0xC0DECAFE) {
        printf("Secret 2 unlocked!\\n");
        // ... perhaps trigger a bug here ...
    }
    
    // (6) IJON_DIST: guide towards satisfying a numeric relation
    IJON_DIST(a + b, 1000);       // reward making (a+b) closer to 1000
    if ((a + b) == 1000) {
        puts("Reached target sum.");
    }
    
    // (7) IJON_STRDIST: guide towards matching a string prefix
    IJON_STRDIST(s, "OPEN");     // reward inputs that match "OPEN" prefix increasingly
    if (strcmp(s, "OPEN") == 0) {
        puts("Opened!");
        // ... maybe a vulnerable condition here ...
    }
    
    // (8) IJON_MAX / IJON_MIN: optimize certain values
    long score = compute_score(s);  
    IJON_MAX(score);            // encourage maximizing the score achieved by input string
    int int_diff = abs(a - b)
    IJON_MIN(int_diff);       // encourage minimizing the difference between a and b
    // With IJON_MAX, the fuzzer will keep inputs that raise 'score'. 
    // With IJON_MIN, it will try to make a and b as close as possible (difference -> 0).
    
    return 0;
}
