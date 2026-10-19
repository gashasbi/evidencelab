/* EvidenceLab synthetic corpus | CWE-134 | VULN
 * Intent: Untrusted input is used as a format string.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <stdio.h>
void sample(const char *user) {
    printf(user); /* VULN: user controls the format string */
}
