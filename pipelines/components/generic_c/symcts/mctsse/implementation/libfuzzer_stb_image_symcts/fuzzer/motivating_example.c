#include <sys/types.h>
#include <stdbool.h>

#define true 1
#define false 0
#define bool int

bool is_valid_png(char *data, int size) {
    if (memcmp(data, "\x89PNG\r\n\x1a\n", 8)) {
        return false;
    }
    bool has_IHDR = false, has_IDAT = false,
         has_IEND = false;
    char *p_chunk = data + 8;
    char *p_end = data + size;
    while (p_chunk < p_end) {
        int size = *(u_int32_t*)p_chunk;
        int type = *(u_int32_t*)(p_chunk+4);
        if (type == "IHDR")
            has_IHDR = true;
        if (type == "IDAT")
            has_IDAT = true;
        if (type == "IEND")
            has_IEND = true;
        p_chunk += size + 12;
    }
    if (has_IHDR && has_IDAT && has_IEND)
      return true;
    else
      return false;
}