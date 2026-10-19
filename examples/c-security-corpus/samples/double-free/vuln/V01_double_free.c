/* EvidenceLab synthetic corpus | CWE-415 | VULN
 * Intent: Frees the same allocation twice.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <stdlib.h>
void sample(void) {
    int *p = malloc(sizeof *p);
    if (!p) return;
    free(p);
    free(p); /* VULN: same allocation released twice */
}
