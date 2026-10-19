/* EvidenceLab synthetic corpus | CWE-798 | VULN
 * Intent: Contains a hard-coded credential used for authentication.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <string.h>
int sample(const char *user, const char *password) {
    return user && password &&
           strcmp(user, "service") == 0 &&
           strcmp(password, "example-password") == 0;
    /* VULN: example credential is embedded in source */
}
