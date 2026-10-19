/* EvidenceLab synthetic corpus | CWE-401 | VULN
 * Intent: Early return leaks an allocation.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <stdlib.h>
int sample(int fail) {
    int *p = malloc(sizeof *p);
    if (!p) return -1;
    if (fail) return -2; /* VULN: allocation leaks on this path */
    free(p);
    return 0;
}
