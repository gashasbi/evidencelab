/* EvidenceLab synthetic corpus | CWE-416 | SAFE
 * Intent: Uses the object before releasing it.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <stdlib.h>
int sample(void) {
    int *p = malloc(sizeof *p);
    if (!p) return -1;
    *p = 10;
    int result = *p;
    free(p);
    return result;
}
