/* EvidenceLab synthetic corpus | CWE-121 | VULN
 * Intent: Unbounded copy into a fixed-size stack buffer.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <string.h>
void sample(const char *input) {
    char buf[16];
    strcpy(buf, input); /* VULN: destination capacity is not enforced */
}
