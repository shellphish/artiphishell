#include "div_lib.h"


#define DIV(name) DIV_DECL(name) \
{ \
    return glue(_, name)(in_eax, in_edx, in_denom, out_eax, out_edx); \
}

DIV(divb)
DIV(idivb)
DIV(divw)
DIV(idivw)
DIV(divl)
DIV(idivl)
DIV(divq)
DIV(idivq)
