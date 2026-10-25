/* EvidenceLab synthetic corpus | CWE-122 | VULN
 * Intent: Unbounded copy into a small heap allocation.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <stdlib.h>
#include <string.h>
void sample(const char *input) {
    char *p = malloc(8);
    if (!p) return;
    strcpy(p, input); /* VULN: allocation may be too small */
    free(p);
}
