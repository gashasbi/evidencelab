/* EvidenceLab synthetic corpus | CWE-190 | SAFE
 * Intent: Checks multiplication bounds before allocating.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <stdint.h>
#include <stdlib.h>
void sample(size_t count) {
    if (count > SIZE_MAX / sizeof(int)) return;
    int *p = malloc(count * sizeof *p);
    free(p);
}
