/* EvidenceLab synthetic corpus | CWE-476 | VULN
 * Intent: Dereferences a possibly NULL allocation result.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <stdlib.h>
int sample(void) {
    int *p = malloc(sizeof *p);
    *p = 42; /* VULN: allocation result is unchecked */
    free(p);
    return 0;
}
