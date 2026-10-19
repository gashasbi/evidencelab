#include <stdio.h>

/* Exploratory: formatted-output writes are outside the two current families. */
void format_input(const char *input) {
    char buffer[16];
    sprintf(buffer, "%s", input);
}
