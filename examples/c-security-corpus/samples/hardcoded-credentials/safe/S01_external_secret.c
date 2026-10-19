/* EvidenceLab synthetic corpus | CWE-798 | SAFE
 * Intent: Loads a secret from configuration instead of embedding it.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <stdlib.h>
int sample(void) {
    const char *secret = getenv("APP_SECRET");
    return secret && secret[0] != '\0';
    /* Deployment must still protect the environment/configuration. */
}
