/* EvidenceLab synthetic corpus | CWE-78 | VULN
 * Intent: Untrusted input is concatenated into a shell command.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <stdlib.h>
#include <stdio.h>
void sample(const char *user) {
    char command[256];
    snprintf(command, sizeof command, "tool %s", user);
    system(command); /* VULN: input reaches a shell command */
}
