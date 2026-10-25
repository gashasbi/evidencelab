/* EvidenceLab synthetic corpus | CWE-327 | VULN
 * Intent: Uses a fast general-purpose hash for a password-storage scenario.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <stddef.h>
extern void md5(const unsigned char *, size_t, unsigned char out[16]);
void sample(const unsigned char *password, size_t n, unsigned char out[16]) {
    md5(password, n, out); /* VULN for password storage: fast unsalted hash */
}
