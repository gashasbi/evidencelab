/* EvidenceLab synthetic corpus | CWE-415 | SAFE
 * Intent: Clears the pointer after release.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <stdlib.h>
void sample(void) {
    int *p = malloc(sizeof *p);
    if (!p) return;
    free(p);
    p = NULL;
    free(p);
}
