#include <string.h>

/* C++ source smoke case for the fixed-write reference family. */
void copy_data_cpp(char *input) {
    char buffer[32];
    memcpy(buffer, input, 64);
}
