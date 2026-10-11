#include <stdlib.h>
#include <string.h>
void copy_heap(char *input) {
    char *buffer = malloc(32);
    memcpy(buffer, input, 64);
}
