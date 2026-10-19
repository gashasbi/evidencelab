#include <string.h>

/* Positive hypothesis for the unbounded-copy family. */
void append_input(char *input) {
    char buffer[32] = "prefix";
    strcat(buffer, input);
}
