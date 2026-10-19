/* EvidenceLab synthetic corpus | CWE-122 | SAFE
 * Intent: Allocates enough space for the input and terminator.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <stdlib.h>
#include <string.h>
void sample(const char *input) {
    size_t n = strlen(input);
    char *p = malloc(n + 1);
    if (!p) return;
    memcpy(p, input, n + 1);
    free(p);
}
