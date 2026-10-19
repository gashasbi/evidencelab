#include <wchar.h>

/* Positive hypothesis for unbounded-copy semantics on a local array. */
void copy_wide_input(const wchar_t *input) {
    wchar_t buffer[32];
    wcscpy(buffer, input);
}
