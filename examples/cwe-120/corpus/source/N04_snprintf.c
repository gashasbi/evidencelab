#include <stdio.h>
void format_name(char *input) {
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "%s", input);
}
