#ifndef DIV_LIB_H
#define DIV_LIB_H

#include <assert.h>
#include <signal.h>
#include <fenv.h>
#include <setjmp.h>

#define xglue(x, y) x ## y
#define glue(x, y) xglue(x, y)

#define DIV_DECL(name) int name(unsigned long in_eax, unsigned long in_edx, unsigned long in_denom, unsigned long* out_eax, unsigned long* out_edx)
DIV_DECL(divb);
DIV_DECL(idivb);
DIV_DECL(divw);
DIV_DECL(idivw);
DIV_DECL(divl);
DIV_DECL(idivl);
DIV_DECL(divq);
DIV_DECL(idivq);

static sigjmp_buf fpe;
static void fpe_handler(int signal_number) {
    feclearexcept(FE_OVERFLOW | FE_UNDERFLOW | FE_DIVBYZERO | FE_INVALID);
    assert(signal_number != 0);
    siglongjmp(fpe, signal_number);
    return;
}

#define RETURN_ERROR_ON_FPE() signal(SIGFPE, fpe_handler); \
    int fpe_error = sigsetjmp(fpe, 1); \
    if (fpe_error) { \
        return fpe_error; \
    } \

#define CLEANUP_ERROR_HANDLING() signal(SIGFPE, SIG_DFL);

static inline int _divb(unsigned long in_eax, unsigned long in_edx, unsigned long in_denom, unsigned long* out_eax, unsigned long* out_edx)
{
    // setup signal handler to catch SIGFPE and return false on error
    RETURN_ERROR_ON_FPE();
    unsigned long out_eax_tmp, out_edx_tmp;
    asm(
        "divb %b4"
        : "=a"(out_eax_tmp), "=d"(out_edx_tmp)
        : "a"(in_eax), "d"(in_edx), "c"(in_denom)
    );
    *out_eax = out_eax_tmp;
    *out_edx = out_edx_tmp;
    CLEANUP_ERROR_HANDLING();
    return 0;
}

static inline int _idivb(unsigned long in_eax, unsigned long in_edx, unsigned long in_denom, unsigned long* out_eax, unsigned long* out_edx)
{
    RETURN_ERROR_ON_FPE();
    unsigned long out_eax_tmp, out_edx_tmp;
    asm(
        "idivb %b4"
        : "=a"(out_eax_tmp), "=d"(out_edx_tmp)
        : "a"(in_eax), "d"(in_edx), "c"(in_denom)
    );
    *out_eax = out_eax_tmp;
    *out_edx = out_edx_tmp;
    CLEANUP_ERROR_HANDLING();
    return 0;
}

static inline int _divw(register unsigned long in_eax, register unsigned long in_edx, register unsigned long in_denom,
                        unsigned long* out_eax, unsigned long* out_edx)
{
    RETURN_ERROR_ON_FPE();
    unsigned long out_eax_tmp, out_edx_tmp;
    asm(
        "divw %w4"
        : "=a"(out_eax_tmp), "=d"(out_edx_tmp)
        : "a"(in_eax), "d"(in_edx), "c"(in_denom)
    );
    *out_eax = out_eax_tmp;
    *out_edx = out_edx_tmp;
    CLEANUP_ERROR_HANDLING();
    return 0;
}
static inline int _idivw(unsigned long in_eax, unsigned long in_edx, unsigned long in_denom, unsigned long* out_eax, unsigned long* out_edx)
{
    RETURN_ERROR_ON_FPE();
    unsigned long out_eax_tmp, out_edx_tmp;
    asm(
        "idivw %w4"
        : "=a"(out_eax_tmp), "=d"(out_edx_tmp)
        : "a"(in_eax), "d"(in_edx), "c"(in_denom)
    );
    *out_eax = out_eax_tmp;
    *out_edx = out_edx_tmp;
    CLEANUP_ERROR_HANDLING();
    return 0;
}

static inline int _divl(unsigned long in_eax, unsigned long in_edx, unsigned long in_denom, unsigned long* out_eax, unsigned long* out_edx)
{
    RETURN_ERROR_ON_FPE();
    unsigned long out_eax_tmp, out_edx_tmp;
    asm(
        "divl %k4"
        : "=a"(out_eax_tmp), "=d"(out_edx_tmp)
        : "a"(in_eax), "d"(in_edx), "c"(in_denom)
    );
    *out_eax = out_eax_tmp;
    *out_edx = out_edx_tmp;
    CLEANUP_ERROR_HANDLING();
    return 0;
}
static inline int _idivl(unsigned long in_eax, unsigned long in_edx, unsigned long in_denom, unsigned long* out_eax, unsigned long* out_edx)
{
    RETURN_ERROR_ON_FPE();
    unsigned long out_eax_tmp, out_edx_tmp;
    asm(
        "idivl %k4"
        : "=a"(out_eax_tmp), "=d"(out_edx_tmp)
        : "a"(in_eax), "d"(in_edx), "c"(in_denom)
    );
    *out_eax = out_eax_tmp;
    *out_edx = out_edx_tmp;
    CLEANUP_ERROR_HANDLING();
    return 0;
}

static inline int _divq(unsigned long in_eax, unsigned long in_edx, unsigned long in_denom, unsigned long* out_eax, unsigned long* out_edx)
{
    RETURN_ERROR_ON_FPE();
    unsigned long out_eax_tmp, out_edx_tmp;
    asm(
        "divq %4"
        : "=a"(out_eax_tmp), "=d"(out_edx_tmp)
        : "a"(in_eax), "d"(in_edx), "c"(in_denom)
    );
    *out_eax = out_eax_tmp;
    *out_edx = out_edx_tmp;
    CLEANUP_ERROR_HANDLING();
    return 0;
}
static inline int _idivq(unsigned long in_eax, unsigned long in_edx, unsigned long in_denom, unsigned long* out_eax, unsigned long* out_edx)
{
    RETURN_ERROR_ON_FPE();
    unsigned long out_eax_tmp, out_edx_tmp;
    asm(
        "idivq %4"
        : "=a"(out_eax_tmp), "=d"(out_edx_tmp)
        : "a"(in_eax), "d"(in_edx), "c"(in_denom)
    );
    *out_eax = out_eax_tmp;
    *out_edx = out_edx_tmp;
    CLEANUP_ERROR_HANDLING();
    return 0;
}
#endif