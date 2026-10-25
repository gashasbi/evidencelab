/* EvidenceLab synthetic corpus | CWE-121 | SAFE
 * Intent: Rejects input that cannot fit, including the terminator.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <string.h>
void sample(const char *input) {
    char buf[16];
    size_t n = strlen(input);
    if (n >= sizeof buf) return;
    memcpy(buf, input, n + 1);
}
