#include <string.h>

/* The fixed extent does not exceed the destination array capacity. */
void copy_bounded(char *input) {
    char buffer[32];
    strncpy(buffer, input, sizeof(buffer));
}
