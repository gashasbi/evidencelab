/* EvidenceLab synthetic corpus | CWE-704 | VULN
 * Intent: Negative signed value is converted to an unsigned size.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <stddef.h>
void sample(int input) {
    size_t length = (size_t)input;
    /* VULN: a negative input becomes a very large unsigned value */
    (void)length;
}
