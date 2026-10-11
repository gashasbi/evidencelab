#include <string.h>
void copy_data(char *input) {
    char buffer[32];
    if (strlen(input) < sizeof(buffer)) {
        strcpy(buffer, input);
    }
}
