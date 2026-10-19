/* EvidenceLab synthetic corpus | CWE-22 | SAFE
 * Intent: Rejects obvious traversal forms; not a complete filesystem proof.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <string.h>
int sample(const char *name) {
    if (!name || name[0] == '/') return -1;
    if (strstr(name, "..")) return -1;
    return 0;
    /* Illustrative only: robust path containment needs canonical checks. */
}
