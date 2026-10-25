/* EvidenceLab synthetic corpus | CWE-22 | VULN
 * Intent: Untrusted path is joined without containment validation.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <stdio.h>
void sample(const char *user_path) {
    char path[256];
    snprintf(path, sizeof path, "/srv/data/%s", user_path);
    FILE *f = fopen(path, "r"); /* VULN: traversal is not rejected */
    if (f) fclose(f);
}
