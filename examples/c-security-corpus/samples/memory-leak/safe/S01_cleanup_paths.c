/* EvidenceLab synthetic corpus | CWE-401 | SAFE
 * Intent: Releases memory on both paths.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <stdlib.h>
int sample(int fail) {
    int *p = malloc(sizeof *p);
    if (!p) return -1;
    if (fail) { free(p); return -2; }
    free(p);
    return 0;
}
