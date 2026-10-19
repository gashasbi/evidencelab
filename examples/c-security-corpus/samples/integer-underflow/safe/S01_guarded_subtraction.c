/* EvidenceLab synthetic corpus | CWE-191 | SAFE
 * Intent: Checks the subtraction precondition.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <stddef.h>
size_t sample(size_t capacity, size_t used) {
    if (used > capacity) return 0;
    return capacity - used;
}
