/* EvidenceLab synthetic corpus | CWE-191 | VULN
 * Intent: Unsigned subtraction may wrap.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <stddef.h>
size_t sample(size_t capacity, size_t used) {
    return capacity - used; /* VULN if used exceeds capacity */
}
