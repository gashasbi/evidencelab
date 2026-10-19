/* EvidenceLab synthetic corpus | CWE-330 | SAFE
 * Intent: Uses an operating-system randomness API; error handling is explicit.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <sys/random.h>
#include <sys/types.h>
int sample(unsigned char *out, unsigned long n) {
    return getrandom(out, n, 0) == (ssize_t)n ? 0 : -1;
}
