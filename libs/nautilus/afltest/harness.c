#include <stdlib.h>
#include <stdio.h>

int main(int argc, char** argv) {
    // read in file
    FILE *fileptr = fopen(argv[1], "rb");  // Open the file in binary mode
    fseek(fileptr, 0, SEEK_END);          // Jump to the end of the file
    size_t filelen = ftell(fileptr);             // Get the current byte offset in the file
    rewind(fileptr);                      // Jump back to the beginning of the file
    char *chunk = malloc(filelen + 1);
    fread(chunk, filelen, 1, fileptr); // Read in the entire file
    chunk[filelen] = 0; 

    printf(chunk);

    return 0;
}