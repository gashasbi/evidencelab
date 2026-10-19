/* EvidenceLab synthetic corpus | CWE-190 | VULN
 * Intent: Allocation-size multiplication may overflow.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <stdlib.h>
void sample(unsigned count) {
    int *p = malloc(count * sizeof *p);
    if (!p) return;
    /* VULN: multiplication may wrap before allocation */
    free(p);
}
