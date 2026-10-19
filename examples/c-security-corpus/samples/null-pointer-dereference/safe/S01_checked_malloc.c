/* EvidenceLab synthetic corpus | CWE-476 | SAFE
 * Intent: Checks allocation before dereference.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <stdlib.h>
int sample(void) {
    int *p = malloc(sizeof *p);
    if (!p) return -1;
    *p = 42;
    free(p);
    return 0;
}
