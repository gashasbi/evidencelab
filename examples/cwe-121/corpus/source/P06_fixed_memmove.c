#include <string.h>

/* Positive hypothesis for fixed-extent writes. */
void move_data(char *input) {
    char buffer[32];
    memmove(buffer, input, 64);
}
