/* EvidenceLab synthetic corpus | CWE-134 | SAFE
 * Intent: Uses a constant format string.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <stdio.h>
void sample(const char *user) {
    printf("%s", user);
}
