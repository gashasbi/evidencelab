/* EvidenceLab synthetic corpus | CWE-330 | VULN
 * Intent: Uses a predictable pseudo-random generator for token material.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <stdlib.h>
void sample(unsigned char *out, unsigned n) {
    for (unsigned i = 0; i < n; ++i)
        out[i] = (unsigned char)rand(); /* VULN for security tokens */
}
