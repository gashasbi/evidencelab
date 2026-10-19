/* EvidenceLab synthetic corpus | CWE-117 | VULN
 * Intent: Untrusted line breaks may forge log entries.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <stdio.h>
void sample(const char *user) {
    fprintf(stderr, "login=%s\n", user);
    /* VULN if embedded newlines can forge additional log records */
}
