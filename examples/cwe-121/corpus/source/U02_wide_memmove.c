#include <wchar.h>

/* The extent is in wide elements; byte capacity is not inferred here. */
void move_wide_data(const wchar_t *input) {
    wchar_t buffer[32];
    wmemmove(buffer, input, 64);
}
