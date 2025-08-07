#include <stdint.h>
#include <assert.h>
#include <sys/types.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

// #define STBI_ASSERT(x)

#define STBI_NO_SIMD
#define STBI_NO_LINEAR
#define STBI_NO_STDIO
#define STB_IMAGE_IMPLEMENTATION

// #define STBI_NO_JPEG
// #define STBI_NO_BMP
// #define STBI_NO_PSD
// #define STBI_NO_TGA
// #define STBI_NO_GIF
// #define STBI_NO_HDR
// #define STBI_NO_PIC
// #define STBI_NO_PNM

#include "stb_image.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    int x, y, channels;

    if(!stbi_info_from_memory(data, size, &x, &y, &channels)) {
        const char* fail = stbi_failure_reason();
        if (fail) {
            fprintf(stderr, "stbi_failure_reason: %s\n", fail);
        }
        return 0;
    }

    /* exit if the image is larger than ~80MB */
    if(y && x > (80000000 / 4) / y) return 0;

    unsigned char *img = stbi_load_from_memory(data, size, &x, &y, &channels, 4);

    if (!img) {
        const char* fail = stbi_failure_reason();
        if (fail) {
            fprintf(stderr, "stbi_failure_reason: %s\n", fail);
        }
    }

    free(img);

	// if (x > 10000) free(img); // free crash

    return 0;
}

#ifdef WITH_MAIN
#include "libfuzzer-main.c"
#endif


#ifdef __cplusplus
}
#endif
