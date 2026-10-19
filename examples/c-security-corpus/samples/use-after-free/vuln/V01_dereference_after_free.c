/* EvidenceLab synthetic corpus | CWE-416 | VULN
 * Intent: Reads an object after freeing it.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <stdlib.h>
int sample(void) {
    int *p = malloc(sizeof *p);
    if (!p) return -1;
    *p = 10;
    free(p);
    return *p; /* VULN: use after free */
}
