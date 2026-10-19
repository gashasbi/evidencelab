/* EvidenceLab synthetic corpus | CWE-78 | SAFE
 * Intent: Uses an argument vector rather than a shell command string.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <unistd.h>
void sample(const char *user) {
    char *const argv[] = {"/usr/bin/tool", (char *)user, NULL};
    execv(argv[0], argv); /* no shell; argument validation may still be needed */
}
