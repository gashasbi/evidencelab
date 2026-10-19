#include <stdlib.h>
#include <string.h>

/* A heap destination is not evidence for the stack-based family. */
void copy_to_heap(char *input) {
    char *buffer = (char *)malloc(32);
    if (buffer != NULL) {
        memcpy(buffer, input, 64);
        free(buffer);
    }
}
