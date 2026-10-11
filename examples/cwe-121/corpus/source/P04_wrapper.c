#include <string.h>
static void helper(char *dst, char *src){ memcpy(dst, src, 64); }
void wrapper(char *input){ char buffer[32]; helper(buffer, input); }
