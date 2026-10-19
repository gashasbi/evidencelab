/* EvidenceLab synthetic corpus | CWE-704 | SAFE
 * Intent: Rejects negative values before conversion.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <stddef.h>
int sample(int input, size_t *out) {
    if (input < 0 || !out) return -1;
    *out = (size_t)input;
    return 0;
}
