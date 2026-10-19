#include <string.h>

/* The extent is a constant expression, not a literal node. */
void copy_expression_extent(char *input) {
    char buffer[32];
    memcpy(buffer, input, 16 * 4);
}
